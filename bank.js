"use strict";

const blindSignatures = require('blind-signatures');

const { Coin, COIN_RIS_LENGTH, IDENT_STR, BANK_STR, NUM_COINS_REQUIRED } = require('./coin.js');
const utils = require('./utils.js');

// This class represents a bank issuing DigiCash-lite coins.
class Bank {
  constructor() {
    this.key = blindSignatures.keyGeneration({ b: 2048 });
    this.ledger = {};
    this.coinDB = {}; // tracks previously redeemed coins
  }

  // Returns the modulus used for digital signatures.
  get n() {
    return this.key.keyPair.n.toString();
  }

  // Returns the e value used for digital signatures.
  get e() {
    return this.key.keyPair.e.toString();
  }

  // Prints out the balances for all of the bank's customers.
  showBalances() {
    console.log(JSON.stringify(this.ledger));
  }

  // Initializes a client's account with 0 value.
  registerClient(client) {
    this.ledger[client.name] = 0;
  }

  // Updates the ledger to account for money submitted directly to the bank.
  deposit({account, amount}) {
    if (this.ledger[account] === undefined) {
      throw new Error(`${account} is not a registered customer of the bank`);
    }
    this.ledger[account] += amount;
  }

  // Updates the ledger to account for money withdrawn directly from the bank.
  withdraw({account, amount}) {
    if (this.ledger[account] === undefined) {
      throw new Error(`${account} is not a registered customer of the bank`);
    }
    if (this.ledger[account] < amount) {
      throw new Error("Insufficient funds");
    }
    this.ledger[account] -= amount;
  }

  // Returns the balance for the specified account.
  balance(account) {
    if (this.ledger[account] === undefined) {
      throw new Error(`${account} is not a registered customer of the bank`);
    }
    return this.ledger[account];
  }

  // Transfers money between 2 of the bank's customers.
  transfer({from, to, amount}) {
    if (this.ledger[from] === undefined) {
      throw new Error(`${from} is not a registered customer of the bank`);
    }
    if (this.ledger[to] === undefined) {
      throw new Error(`${to} is not a registered customer of the bank`);
    }
    let fromBalance = this.ledger[from];
    if (fromBalance < amount) {
      throw new Error(`${from} does not have sufficient funds`);
    }
    this.ledger[from] = fromBalance - amount;
    this.ledger[to] += amount;
  }

  // Verifies that a bank customer has sufficient funds for a transaction.
  verifyFunds({account, amount}) {
    if (this.ledger[account] === undefined) {
      throw new Error(`${account} is not a registered customer of the bank`);
    }
    let balance = this.ledger[account];
    return balance >= amount;
  }

  // This method represents the bank's side of the exchange when a user buys a coin.
  sellCoin(account, amount, coinBlindedHashes, response) {
    let selected = utils.randInt(NUM_COINS_REQUIRED - 1); // returns a randomly selected coin.
 
    let cbf = response(selected); // returns blinding factors and the matching coins of all the coins except selected.
    let identity;

    for(let i in cbf[1]){
      let x = cbf[1][i];
      if(!x.verifyUnblinded(cbf[0][i])){
        throw new Error("Blind factors dont match");
      }

    for(let j = 0; j < NUM_COINS_REQUIRED; j++){
      identity = utils.decryptOTP({key: cbf[1][i].leftIdent[j], ciphertext: cbf[1][i].rightIdent[j], returnType: "string"});
        if(identity !== ("IDENT:" +  account)){
          throw new Error("Identity invalid");
      }
    }
  }
    let sig = blindSignatures.sign({blinded: coinBlindedHashes[selected], key: this.key});
    this.withdraw({account, amount});
    return sig;
}

  // Adds a coin to a user's bank account.
  redeemCoin({account, coin, ris}) {
    blindSignatures.verify({
      unblinded: coin.signature,
      N: this.n,
      E: this.e,
      message: coin.toString()
    });

    if(!(coin.guid in this.coinDB)){
      console.log(`Coin #${coin.guid} has been redeemed. Have a nice day.`)
      this.coinDB[coin.guid] = ris;
      let balance  = this.ledger[account];
      this.ledger[account] = balance + coin.amount;
    }

    else{
      console.log(`Coin ${coin.guid} previously spent.  Determining cheater.`)
    for(let i = 0; i < ris.length ; i++){
      let identStr = utils.decryptOTP({
        key: ris[i],
        ciphertext: this.coinDB[coin.guid][i],
        returnType: 'string'
      });

      if(identStr.startsWith(IDENT_STR)){
        let cheater = identStr.split(':')[1];
        console.log(`${cheater} double spent coin ${coin.guid}.`);
        console.log(`Sorry, but coin ${coin.guid} cannot be accepted.`);
        return;
      }
    }
    console.log("The merchant tried to redeem the coin twice");
    console.log(`Sorry, but coin ${coin.guid} cannot be accepted.`);
  }
  }
}

exports.Bank = Bank;
