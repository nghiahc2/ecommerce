"use strict";

const shopModel = require("../models/shop.model");
const bcrypt = require("bcrypt");
//const crypto = require('crypto')
const crypto = require("node:crypto");
const KeyTokenService = require("./keyToken.service");
const { createTokenPair } = require("../auth/authUtils");
const { getInfoData } = require("../utils");
const { BadRequestError, AuthFailureError } = require("../core/error.response");
const { token } = require("morgan");
const { findByEmail } = require("./shop.service");

const RoleShop = {
  SHOP: "SHOP",
  WRITER: "WRITER",
  EDITOR: "EDITOR",
  ADMIN: "ADMIN",
};

class AccessService {
  static logout = async (keyStore) => {
    const { _id } = await KeyTokenService.removeKeyById(keyStore._id);
    return _id;
  };

  // 1 - check email in dbs
  // 2 - match password
  // 3 - create AT and RT and SVGAElement
  // 4 - generate token
  // 5 - get data return login
  static login = async ({ email, password, refreshToken = null }) => {
    // 1.
    const foundShop = await findByEmail({ email });
    if (!foundShop) throw new BadRequestError("Shop not registered!");

    // 2.
    const match = bcrypt.compare(password, foundShop.password);
    if (!match) throw new AuthFailureError("Authentication error");

    // 3.
    // create AT and RT
    const privateKey = crypto.randomBytes(64).toString("hex");
    const publicKey = crypto.randomBytes(64).toString("hex");

    // 4. generate token
    const { _id: userId } = foundShop;
    const tokens = await createTokenPair(
      { userId, email },
      publicKey,
      privateKey
    );

    await KeyTokenService.createKeyToken({
      userId,
      refreshToken: tokens.refreshToken,
      privateKey,
      publicKey,
    });

    return {
      shop: getInfoData({
        fields: ["_id", "name", "email"],
        object: foundShop,
      }),
      tokens,
    };
  };

  static signUp = async ({ name, email, password }) => {
    //try {
    // step1: check email exists??
    const holderShop = await shopModel.findOne({ email }).lean();
    if (holderShop) {
      throw new BadRequestError("Error: Shop already registered!");
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const newShop = await shopModel.create({
      name,
      email,
      password: passwordHash,
      roles: [RoleShop.SHOP],
    });
    if (newShop) {
      // create privateKey, publicKey
      // const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      //     modulusLength: 4096,
      //     publicKeyEncoding: {
      //         type: 'pkcs1',
      //         format: 'pem'
      //     },
      //     privateKeyEncoding: {
      //         type: 'pkcs1',
      //         format: 'pem'
      //     }
      // })

      const privateKey = crypto.randomBytes(64).toString("hex");
      const publicKey = crypto.randomBytes(64).toString("hex");

      console.log({ privateKey, publicKey }); // save collection KeyStore

      // const publicKeyString = await KeyTokenService.createKeyToken({
      //     userId: newShop._id,
      //     publicKey,
      //     privateKey
      // })
      // if (!publicKeyString) {
      //     return {
      //         code: 'xxxx',
      //         message: 'publicKeyString error'
      //     }
      // }

      const keyStore = await KeyTokenService.createKeyToken({
        userId: newShop._id,
        publicKey,
        privateKey,
      });

      if (!keyStore) {
        return {
          code: "xxxx",
          message: "keyStore error",
        };
      }

      //const publicKeyObject = crypto.createPublicKey(publicKeyString);
      // created token pair
      //const tokens = await createTokenPair({ userId: newShop._id, email }, publicKeyObject, privateKey)
      //console.log('Created Token Success::', tokens)

      const tokens = await createTokenPair(
        { userId: newShop._id, email },
        publicKey,
        privateKey
      );

      return {
        code: 201,
        metadata: {
          shop: getInfoData({
            fields: ["_id", "name", "email"],
            object: newShop,
          }),
          tokens,
        },
      };
    }
    // } catch (error) {
    //     return {
    //         code: 'xxx',
    //         message: error.message,
    //         status: 'error'
    //     }
    // }
  };
}

module.exports = AccessService;
