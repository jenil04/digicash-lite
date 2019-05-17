"use strict";

const blindSignatures = require('blind-signatures');

const { Coin, COIN_RIS_LENGTH, IDENT_STR, BANK_STR, NUM_COINS_REQUIRED } = require('./coin.js');

const utils = require('./utils.js');

const TOKEN_RIS_LENGTH = 20;

// Simple class simulating a client in out network.
// For simplicity sake, a client can only hold 1 coin at a time.
class Client {

  // Every client must have a name to identify them.
  constructor(name) {
    this.name = name;
  }

  // Buys a coin from the bank, calling the bank's "sellCoin" method.
  // This approach uses a "cut-and-choose" strategy so that the bank
  // will sign the coin without seeing it.
  buyCoin(bank, amount) {
    if (!!this.coin) {
      throw new Error('Already have a coin');
    }
    let coins = [];
    let blindingFactors = [];
    let blindedHashes = [];
    for (let i=0; i<NUM_COINS_REQUIRED; i++) {
      coins[i] = new Coin(this.name, amount, bank.n, bank.e);
      blindingFactors[i] = coins[i].blind();
      blindedHashes[i] = coins[i].blinded;
    }
    let bf;
    let signature = bank.sellCoin(this.name, amount, blindedHashes, (selected) => {
      this.coin = coins[selected];
      bf = blindingFactors[selected];

      delete coins[selected];
      return [blindingFactors, coins];
    });

    this.coin.signature = signature;
    this.coin.unblind(bf);
  }

  // Transfers a coin to another user, deleting it from this user.
  giveCoin(other) {
    if (!this.coin) {
      throw new Error('Do not have a coin');
    } else if (!!other.coin) {
      throw new Error(`${other.name} already have a coin`);
    }
    other.acceptCoin(this.coin);
    delete this.coin;
  }

  // Procedure for a client accepting a token.
  // The client randomly selects the left or
  // right halves of the identity string.
  acceptCoin(coin) {
    let cs = coin.toString();
    let valid = blindSignatures.verify({
        unblinded: coin.signature,
        N: coin.n,
        E: coin.e, 
        message: cs
    });

    if(!valid){
        throw new Error("Bad signature.");
    }

    let [lh, rh] = Coin.parseCoin(cs);
    let ris = [];
    for(let i = 0; i < lh.length; i++){
        let isLeft = !!utils.randInt(2);
        let identHalf = coin.getRis(isLeft, i);
        let hashVal = isLeft ? lh[i] : rh[i];
        let h = utils.hash(identHalf);

        if(h !== hashVal){
            throw new Error();
        }
        ris.push(identHalf);
    }
    this.ris = ris;
    this.coin = coin;
  }

  // Deposits the coin to the bank,
  // deleting it from the user.
  redeemCoin(bank) {
    bank.redeemCoin({
        account: this.name,
        coin: this.coin,
        ris: this.ris,
    });
    delete this.coin;
    delete this.ris;
  }
}

exports.Client = Client;