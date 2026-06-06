import anthropic, time, json, os, requests, base64
from dotenv import load_dotenv
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction
load_dotenv()
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
WALLET_ADDRESS = os.getenv('WALLET_ADDRESS')
PRIVATE_KEY = os.getenv('WALLET_PRIVATE_KEY')
MAX_USDC = float(os.getenv('MAX_USDC', 50))
STOP_LOSS = float(os.getenv('STOP_LOSS', 0.03))
TAKE_PROFIT = float(os.getenv('TAKE_PROFIT', 0.05))
INTERVAL = int(os.getenv('INTERVAL', 900))
SOLANA_RPC = 'https://api.mainnet-beta.solana.com'
JUPITER_BASE = 'https://quote-api.jup.ag/v6'
USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
TOKENS = [
    {'mint': 'HMfERpVKozrefwou3dvZEegMdmyiKzeWBBDcsijDpump', 'label': 'TOKEN1'},
    {'mint': 'AqQtvEvV6wTGYjxSmzzWB11K2kmWBwbdfKCNkkW3pump', 'label': 'TOKEN2'},
    {'mint': '6xUoG8JtjYxKfBD3nsLGp8n9pGzKUigF5WTwWyy1pump', 'label': 'TOKEN3'},
    {'mint': 'uuxWwFL6G9UjiYRZvWxJrSB18V1oKBgYrmueamREK57', 'label': 'TOKEN4'},
    {'mint': '6KHeDqkeGc5JKAM9u5UKXZ1uqTeV4o45PAjAruHNpump', 'label': 'TOKEN5'},
    {'mint': 'Ac8EScJ4ufRo8PiFkun7diUrcCCktg4JvArb3mPmpump', 'label': 'TOKEN6'},
    {'mint': 'aLqb3HVkpHardDE992xHf1NBnw55C2f88hkEZ3mpump', 'label': 'TOKEN7'},
    {'mint': '7sgtaBCjEyo1LsPWfsfZXhj7H8q4SX1TJgyBZ7c5pump', 'label': 'TOKEN8'},
    {'mint': 'FeMbDoX7R1Psc4GEcvJdsbNbZA3bfztcyDCatJVJpump', 'label': 'TOKEN9'},
    {'mint': 'ACtfUWtgvaXrQGNMiohTusi5jcx5RJf5zwu9aAxkpump', 'label': 'TOKEN10'},
    {'mint': '78B31QV1rtyoe2EYvVNjBVjeowyrtcH5FPTE4tCypump', 'label': 'TOKEN11'},
    {'mint': 'FzMe8rQ54FRg31KH1sHUbrdPEMMMJbLjNJ8miV8Tpump', 'label': 'TOKEN12'},
]
client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
keypair = Keypair.from_base58_string(PRIVATE_KEY)

def get_token_price(mint):
    try:
        r = requests.get('https://api.dexscreener.com/latest/dex/tokens/' + mint, timeout=10)
        r.raise_for_status()
        pairs = r.json().get('pairs', [])
        if pairs:
            return float(pairs[0]['priceUsd'])
    except: pass
    return None

def get_balance():
    r = requests.post(SOLANA_RPC, json={'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [WALLET_ADDRESS]}, timeout=10)
    return r.json()['result']['value'] / 1e9

def get_usdc_balance():
    r = requests.post(SOLANA_RPC, json={'jsonrpc': '2.0', 'id': 1, 'method': 'getTokenAccountsByOwner', 'params': [WALLET_ADDRESS, {'mint': USDC_MINT}, {'encoding': 'jsonParsed'}]}, timeout=10)
    accounts = r.json().get('result', {}).get('value', [])
    if accounts:
        return float(accounts[0]['account']['data']['parsed']['info']['tokenAmount']['uiAmount'] or 0)
    return 0.0

def ai_decision(label, price, sol, usdc):
    prompt = 'Token:' + label + ' Price:$' + str(price) + ' SOL:' + str(round(sol,4)) + ' USDC:' + str(round(usdc,2)) + ' Solana meme coin. Reply ONLY JSON: {"decision":"BUY|SELL|HOLD","reasoning":"str","confidence":0.5,"amount_pct":0.3}'
    msg = client.messages.create(model='claude-haiku-4-5-20251001', max_tokens=200, system='Cautious Solana meme coin trading agent. JSON only. Be very careful with meme coins.', messages=[{'role': 'user', 'content': prompt}])
    raw = msg.content[0].text.strip()
    if raw.startswith('```'): raw = raw.split('```')[1].lstrip('json')
    return json.loads(raw.strip())

def execute_swap(input_mint, output_mint, amount):
    quote = requests.get(JUPITER_BASE + '/quote', params={'inputMint': input_mint, 'outputMint': output_mint, 'amount': int(amount), 'slippageBps': 100}, timeout=10).json()
    swap_resp = requests.post(JUPITER_BASE + '/swap', json={'quoteResponse': quote, 'userPublicKey': WALLET_ADDRESS, 'wrapAndUnwrapSol': True}, timeout=10).json()
    raw_tx = base64.b64decode(swap_resp['swapTransaction'])
    tx = VersionedTransaction.from_bytes(raw_tx)
    signed_tx = keypair.sign_versioned_transaction(tx)
    result = requests.post(SOLANA_RPC, json={'jsonrpc': '2.0', 'id': 1, 'method': 'sendTransaction', 'params': [base64.b64encode(bytes(signed_tx)).decode(), {'encoding': 'base64'}]}, timeout=30).json()
    return result.get('result', str(result))

def run():
    print('OrcAgent Solana MEME MULTI-TOKEN started')
    print('Wallet: ' + str(WALLET_ADDRESS))
    print('Monitoring ' + str(len(TOKENS)) + ' tokens')
    positions = {t['mint']: {'amount': 0.0, 'buy_price': 0.0} for t in TOKENS}
    while True:
        try:
            sol = get_balance()
            usdc = get_usdc_balance()
            print('SOL:' + str(round(sol,4)) + ' USDC:' + str(round(usdc,2)))
            for token in TOKENS:
                try:
                    price = get_token_price(token['mint'])
                    if price is None:
                        print(token['label'] + ': price not found, skipping')
                        continue
                    pos = positions[token['mint']]
                    res = ai_decision(token['label'], price, sol, usdc)
                    print(token['label'] + ' $' + str(price) + ' [' + res['decision'] + '] ' + res['reasoning'][:50])
                    if res['decision'] == 'BUY' and usdc > 5:
                        spend = min(usdc * res['amount_pct'], MAX_USDC / len(TOKENS))
                        tx = execute_swap(USDC_MINT, token['mint'], int(spend * 1e6))
                        print('BUY ' + token['label'] + ' TX: ' + str(tx))
                        pos['amount'] += spend / price
                        pos['buy_price'] = price
                        usdc -= spend
                    elif res['decision'] == 'SELL' and pos['amount'] > 0:
                        tx = execute_swap(token['mint'], USDC_MINT, int(pos['amount'] * 1e6))
                        print('SELL ' + token['label'] + ' TX: ' + str(tx))
                        usdc += pos['amount'] * price
                        pos['amount'] = pos['buy_price'] = 0.0
                    if pos['amount'] > 0 and pos['buy_price'] > 0:
                        chg = (price - pos['buy_price']) / pos['buy_price']
                        if chg <= -STOP_LOSS or chg >= TAKE_PROFIT:
                            tx = execute_swap(token['mint'], USDC_MINT, int(pos['amount'] * 1e6))
                            print('SL/TP ' + token['label'] + ' ' + str(round(chg*100,1)) + '% TX: ' + str(tx))
                            usdc += pos['amount'] * price
                            pos['amount'] = pos['buy_price'] = 0.0
                except Exception as e:
                    print(token['label'] + ' error: ' + str(e))
            print('Sleeping ' + str(INTERVAL) + 's...')
        except Exception as e:
            print('Error: ' + str(e))
        time.sleep(INTERVAL)

if __name__ == '__main__': run()
