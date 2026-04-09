def simulate_blockchain_supply(total_supply, initial_reward, blocks_per_halving, block_time_seconds=10):
    """
    Simula o supply de uma blockchain baseado no modelo do Bitcoin.

    :param total_supply: Quantidade total de moedas que serão emitidas.
    :param initial_reward: Recompensa inicial por bloco (em moedas).
    :param blocks_per_halving: Número de blocos até que o halving ocorra.
    :param block_time_seconds: Tempo médio para minerar um bloco, em segundos (padrão: 10 segundos).
    """
    current_reward = initial_reward
    current_supply = 0
    block_height = 0
    halvings = 0

    # Calcula o tempo por halving em anos
    halving_time_years = (blocks_per_halving * block_time_seconds) / (60 * 60 * 24 * 365)

    #print("Bloco", "\tRecompensa", "\tSupply Acumulado", "\tTempo Decorrido (anos)")

    while current_supply < total_supply:
        # Verifica se o halving deve ocorrer
        if block_height % blocks_per_halving == 0 and block_height != 0:
            current_reward /= 2
            halvings += 1

            min = 0.01 # 1e-8

            # Previne que a recompensa fique menor do que uma unidade mínima
            if current_reward < min:
                print("Recompensa muito pequena para continuar (menor que 1 satoshi).")
                break

        # Adiciona a recompensa ao supply total
        current_supply += current_reward

        # Evita que o supply exceda o limite total
        if current_supply > total_supply:
            current_supply = total_supply

        # Calcula o tempo decorrido em anos
        time_elapsed_years = (block_height * block_time_seconds) / (60 * 60 * 24 * 365)

        # print(f"{block_height}\t{current_reward:.8f}\t{current_supply:.8f}\t{time_elapsed_years:.2f}")

        block_height += 1

    print("\nSimulação Finalizada!")
    print(f"Altura Final do Bloco: {block_height - 1}")
    print(f"Total de Halvings: {halvings}")
    print(f"Tempo total simulado: {time_elapsed_years:.2f} anos")
    print(f"Supply Total Emitido: {current_supply:.8f}")

# # Parâmetros da blockchain - BTC Example
# TOTAL_SUPPLY = 21000000        # Supply máximo, ex.: 21 milhões como o Bitcoin
# INITIAL_REWARD = 50            # Recompensa inicial por bloco
# BLOCKS_PER_HALVING = 210000    # Número de blocos por halving
# BLOCK_TIME_SECONDS = 600       # Tempo médio de mineração por bloco, em segundos

# Parâmetros da blockchain - AIIR
TOTAL_SUPPLY = 100000000000         # Supply máximo
INITIAL_REWARD = 30              # Recompensa inicial por bloco
BLOCKS_PER_HALVING = 100000000   # Aproximadamente 4 anos com blocos de 1 segundo
BLOCK_TIME_SECONDS = 1           # Tempo médio por bloco

simulate_blockchain_supply(TOTAL_SUPPLY, INITIAL_REWARD, BLOCKS_PER_HALVING, BLOCK_TIME_SECONDS)
