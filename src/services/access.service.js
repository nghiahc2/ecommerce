'use strict'

const shopModel = require("../models/shop.model")
const bcrypt = require('bcrypt')
//const crypto = require('crypto')
const crypto = require('node:crypto')
const KeyTokenService = require("./keyToken.service")
const { createTokenPair } = require("../auth/authUtils")
const { getInfoData } = require("../utils")
const { BadRequestError } = require("../core/error.response")

const RoleShop = {
    SHOP: 'SHOP',
    WRITER: 'WRITER',
    EDITOR: 'EDITOR',
    ADMIN: 'ADMIN'
}

class AccessService {
    static signUp = async ({ name, email, password }) => {
        //try {
        // step1: check email exists??
        const holderShop = await shopModel.findOne({ email }).lean()
        if (holderShop) {
            throw new BadRequestError('Error: Shop already registered!')
        }
        const passwordHash = await bcrypt.hash(password, 10)
        const newShop = await shopModel.create({
            name, email, password: passwordHash, roles: [RoleShop.SHOP]
        })
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

            const privateKey = crypto.randomBytes(64).toString('hex')
            const publicKey = crypto.randomBytes(64).toString('hex')

            console.log({ privateKey, publicKey }) // save collection KeyStore

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
                privateKey
            })

            if (!keyStore) {
                return {
                    code: 'xxxx',
                    message: 'keyStore error'
                }
            }

            //const publicKeyObject = crypto.createPublicKey(publicKeyString);
            // created token pair
            //const tokens = await createTokenPair({ userId: newShop._id, email }, publicKeyObject, privateKey)
            //console.log('Created Token Success::', tokens)

            const tokens = await createTokenPair({ userId: newShop._id, email }, publicKey, privateKey)

            return {
                code: 201,
                metadata: {
                    shop: getInfoData({ fields: ['_id', 'name', 'email'], object: newShop }),
                    tokens
                }
            }
        }
        // } catch (error) {
        //     return {
        //         code: 'xxx',
        //         message: error.message,
        //         status: 'error'
        //     }
        // }
    }
}

module.exports = AccessService