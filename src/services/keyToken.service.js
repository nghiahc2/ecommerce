"use strict";

const { Types } = require("mongoose");
const keytokenModel = require("../models/keytoken.model");

class KeyTokenService {
  static createKeyToken = async ({
    userId,
    publicKey,
    privateKey,
    refreshToken,
  }) => {
    try {
      // level 0
      //const publicKeyString = publicKey.toString()
      //   const tokens = await keytokenModel.create({
      //     user: userId,
      //     //publicKey: publicKeyString
      //     publicKey,
      //     privateKey,
      //   });
      //   return tokens ? publicKeyString : null;

      // level xxx
      const filter = { user: userId },
        update = {
          publicKey,
          privateKey,
          refreshTokenUsed: [],
          refreshToken,
        },
        options = { upsert: true, new: true };
      const tokens = await keytokenModel.findOneAndUpdate(
        filter,
        update,
        options
      );

      return tokens ? tokens.publicKey : null;
    } catch (error) {
      return error;
    }
  };

  static findByUserId = async (userId) => {
    return await keytokenModel.findOne({ user: new Types.ObjectId(userId) });
  };

  static removeKeyById = async (id) => {
    return await keytokenModel.findByIdAndRemove(id);
  };

  static findByRefreshTokensUsed = async (refreshToken) => {
    return await keytokenModel
      .findOne({ refreshTokensUsed: refreshToken })
      .lean();
  };

  static findByRefreshToken = async (refreshToken) => {
    return await keytokenModel.findOne({ refreshToken });
  };

  static deleteKeyById = async (userId) => {
    return await keytokenModel.deleteOne({ user: new Types.ObjectId(userId) });
  };
}

module.exports = KeyTokenService;
