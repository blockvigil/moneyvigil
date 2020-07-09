# Setting up MoneyVigil Backend

The steps below will help you fill in the right details in the settings file. To begin with, copy the `conf.example.json` to `conf.json`

You will need a Linux or Mac OS environment to run this backend.

## Install all required Python modules

`pip install -r requirements.txt`

## Interacting with the Ethereum components

### EthVigil Beta Developer Account

[https://github.com/blockvigil/ethvigil-cli](https://github.com/blockvigil/ethvigil-cli)

Follow the instructions contained in the link above to install `ev-cli`, the CLI tool to interact with EthVigil APIs and also complete your signup for a developer account on EthVigil.

### EthVigil Python SDK

[https://github.com/blockvigil/ethvigil-python-sdk](https://github.com/blockvigil/ethvigil-python-sdk)

With the fresh EthVigil Beta signup and CLI installed, next up is installation of the EthVigil Python SDK. 

Run the following command
```bash
pip install git+https://github.com/blockvigil/ethvigil-python-sdk.git
```
Open up `~/.ethvigil/settings.json` and copy over the following fields to `conf.json`

`"PRIVATEKEY"` to️ `"privatekey"`

`"REST_API_ENDPOINT"` : `"https://beta.ethvigil.com/api"`

"`ETHVIGIL_USER_ADDRESS"` (same field in both files)

`"ETHVIGIL_API_KEY"` (same)

### Deploy `contracts/Main.sol`

Use EthVigil to deploy the Solidity Smart Contract, `Main.sol`. 

* [Deploy contract from Web UI](https://ethvigil.com/docs/web_onboarding/#deploy-a-solidity-smart-contract)
* [Deploy contract from CLI](https://ethvigil.com/docs/cli_onboarding/#deploy-a-solidity-smart-contract)

Fill this deployed contract address in the following field in `conf.json`

{`"contractAddress": "0xContractAddress"}`

### Ethereum Name Service (ENS)

#### Deploy `contracts/MoneyVigilENSHandler.sol`

Register a top level domain on ENS and record the corresponding `namehash` and string in the `conf.json`

```json
{
  "ENSManagerContract": "0xContractAddress",
  "topLevelENSDomain": {
      "name": "topleveldomain.eth",
      "nameHash": "0xNameHash"
  },
```

From the Entity dashboard screen, ensure the displayed contract address is assigned the ownership on the top level ENS domain. For the purpose of this demo, it gives it the right to create further subdomains corresponding to new entity registrations on MoneyVigil.

You hace to call `setOwner(nameHash, ENSManagerContractAddress)` on the contract `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e` (`ENSRegistryWithFallback`)

### Dai and Compound Dai contracts

Fill up the following fields in `conf.json` . You can find these contracts on the Goerli testnet.

```json
{
    "DaiContract": "0xdc31ee1784292379fbb2964b3b9c4124d8f89c60",
    "cDaiContract": "0x822397d9a55d0fefd20F5c4bCaB33C5F65bd28Eb"
}
```

Set up webhook integrations on them by pointing them to the address `webhook_listener.py` is listening on.

Set up the public URL endpoint as a webhook integration for the smart contracts.

* [From Web UI](https://ethvigil.com/docs/web_onboarding/#adding-integrations)
* [From CLI](https://ethvigil.com/docs/cli_onboarding/#adding-integrations)

`http://<URL_ENDPOINT>/dai` for the Dai contract webhook integration
`http://<URL_ENDPOINT>/cdai` for the Compound Dai contract webhook integration

## Databases and cache

### Redis Configuration

You have to fill the appropriate host IP, port numbers and database number into the settings file section as follows (leave the `CLUSTER_MODE` mode set to False):

```
"REDIS": {  
    "HOST": "127.0.0.1",
    "PORT": 6380,
    "DB": 0,
    "PASSWORD": null,
    "CLUSTER_MODE": false
},
  ```

### Neo4j Graph Database 

Enter the right credentials in 

```json 
"NEO4J": {
      "URL": "bolt://neo4j:neo4j@localhost:7687",
      "USERNAME": "neo4j",
      "PASSWORD": "neo4j"
    },
```

### MySQL Relational Database

Enter the appropriate MySQL credentials in the following section in `conf.json`

```json
"MYSQL": {
      "HOST": "192.168.99.100",
      "USER": "root",
      "PASSWORD": "",
      "DB": "hackmoney"
    },
```

#### Alembic + SQLAlchemy for separation of concerns between data models and migration operations. 

### Initialize Graph and Relational DB with a few users

```bash
chmod +x db_reset_instructions.sh
./db_reset_instructions.sh
```

## Amazon SES credentials

The backend code currently uses SES credentials to send out emails. Find the following section in the settings file and fill in the neccessary details:

```
"SES_CREDENTIALS": {  
    "from": "",  
    "region": "",  
    "accessKeyId": "",  
    "secretAccessKey": "",  
    "accountId": 0  
  },
  ```

## Main backend - Flask server

```bash
chmod +x run_flask.sh
./run_flask.sh
```

You can visit `http://localhost:5000` and take a look at the REST API exposed for this project.

## Off-chain data and logic integrator

`python webhook_listener.py`

## Receipts

### Run a Sia node

We can attach receipts and cheques with filed expenses to act as proofs. These are stored on the Sia decentralized storage platform.

We are not using the Skynet APIs. Instead we have been running our own nodes to connect to the Sia chain and speaking directly to it to upload and download the file blobs securely.

### Serve files from Sia

`python receipts_endpoint.py`

This starts a Tornado server that streams files from Sia when provided with unique file hash.