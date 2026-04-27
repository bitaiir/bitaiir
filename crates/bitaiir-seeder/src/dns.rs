//! Authoritative DNS server.
//!
//! When a recursive resolver asks for the configured zone (e.g.
//! `seed.bitaiir.org` IN A), we read the freshest top-N peer list
//! from the DB and reply with their IPv4 addresses.  Every query
//! consults the DB directly: top-N selection is microseconds and
//! we never want to serve stale results.
//!
//! IPv6 / `AAAA` is intentionally out of scope for the v0.1.x
//! seeder — peers we crawl over IPv4 store IPv4 socket addresses,
//! so we'd need a separate AAAA path that doesn't apply yet.
//! See `docs/seeder-operator-guide.md` for the upgrade path.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use hickory_proto::op::{Header, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_server::ServerFuture;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::db::Db;

/// How many A records we cap each response at.  DNS UDP responses
/// are limited to 512 bytes by default; we cap at 16 so the typical
/// UDP reply fits without truncation.  Resolvers that need more can
/// fall back to TCP.
const DNS_RESPONSE_MAX: usize = 16;

/// Window for "recent enough to serve from DNS".
const DNS_RECENT_SECS: u64 = 30 * 60;

/// TTL on the answer records (seconds).  Short so resolvers come
/// back to us when the seed list rotates; not so short that we
/// drown the seeder under a thundering herd.
const DNS_TTL_SECS: u32 = 60;

/// hickory `RequestHandler` implementation backed by the seeder's
/// peer DB.  All queries are answered authoritatively for the
/// configured zone; queries for any other name return REFUSED.
struct SeedHandler {
    db: Arc<Db>,
    zone: LowerName,
    zone_name: Name,
}

#[async_trait]
impl RequestHandler for SeedHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut respond: R,
    ) -> ResponseInfo {
        let q = request.query();

        // Only answer queries for our zone (the apex name).
        // Subdomains are refused — `LowerName` already does
        // case-insensitive comparison.
        if q.name() != &self.zone {
            return reply_with_code(request, &mut respond, ResponseCode::Refused).await;
        }

        // We answer A only.  AAAA, MX, TXT etc. → empty NOERROR
        // (the RFC-clean way to say "exists, but no record of that
        // type").
        if q.query_type() != RecordType::A {
            return reply_empty(request, &mut respond).await;
        }

        let now = unix_now();
        let peers = self
            .db
            .top_for_dns(DNS_RESPONSE_MAX, now, DNS_RECENT_SECS)
            .unwrap_or_default();

        let mut answers: Vec<Record> = Vec::with_capacity(peers.len());
        for p in peers {
            if let IpAddr::V4(v4) = p.ip() {
                let rdata = RData::A(A(v4));
                let rec = Record::from_rdata(self.zone_name.clone(), DNS_TTL_SECS, rdata);
                answers.push(rec);
            }
        }

        let mut header = Header::response_from_request(request.header());
        header.set_message_type(MessageType::Response);
        header.set_op_code(OpCode::Query);
        header.set_authoritative(true);
        header.set_recursion_available(false);

        let builder = MessageResponseBuilder::from_message_request(request);
        let response = builder.build(header, answers.iter(), &[], &[], &[]);
        match respond.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                warn!(target: "seeder.dns", error = %e, "send_response failed");
                ResponseInfo::from(servfail_header())
            }
        }
    }
}

fn servfail_header() -> Header {
    let mut h = Header::new();
    h.set_response_code(ResponseCode::ServFail);
    h
}

async fn reply_with_code<R: ResponseHandler>(
    request: &Request,
    respond: &mut R,
    code: ResponseCode,
) -> ResponseInfo {
    let mut header = Header::response_from_request(request.header());
    header.set_message_type(MessageType::Response);
    header.set_authoritative(true);
    header.set_response_code(code);
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.build_no_records(header);
    respond
        .send_response(response)
        .await
        .unwrap_or_else(|_| ResponseInfo::from(servfail_header()))
}

async fn reply_empty<R: ResponseHandler>(request: &Request, respond: &mut R) -> ResponseInfo {
    let mut header = Header::response_from_request(request.header());
    header.set_message_type(MessageType::Response);
    header.set_authoritative(true);
    let builder = MessageResponseBuilder::from_message_request(request);
    let answers: Vec<Record> = Vec::new();
    let response = builder.build(header, answers.iter(), &[], &[], &[]);
    respond
        .send_response(response)
        .await
        .unwrap_or_else(|_| ResponseInfo::from(servfail_header()))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Spawn the DNS server.  Binds UDP on `listen` and runs until
/// `shutdown` flips to true.  Returns once the server has stopped.
pub async fn run(
    db: Arc<Db>,
    zone: &str,
    listen: &str,
    shutdown: Arc<AtomicBool>,
) -> Result<(), String> {
    let zone_name = Name::from_str(zone).map_err(|e| format!("invalid zone {zone}: {e}"))?;
    let zone_lower: LowerName = zone_name.clone().into();

    let socket = UdpSocket::bind(listen)
        .await
        .map_err(|e| format!("bind UDP {listen}: {e}"))?;
    info!(
        target: "seeder.dns",
        zone = %zone_name,
        listen = %listen,
        "DNS server listening"
    );

    let mut server = ServerFuture::new(SeedHandler {
        db,
        zone: zone_lower,
        zone_name,
    });
    server.register_socket(socket);

    // Poll the shutdown flag in 1 s slices.  When tripped, ask
    // hickory to drain in-flight queries.
    while !shutdown.load(Ordering::Relaxed) {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if let Err(e) = server.shutdown_gracefully().await {
        warn!(target: "seeder.dns", error = %e, "DNS shutdown reported errors");
    }
    Ok(())
}
