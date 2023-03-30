'use strict'

const { CREATED } = require("../core/success.response")
const AccessService = require("../services/access.service")

class AccessController {
    signUp = async (req, res, next) => {
        new CREATED({
            message: 'Registerd!',
            metadata: await AccessService.signUp(req.body),
            options: {
                limits: 10
            }
        }).send(res)
        //return res.status(201).json(await AccessService.signUp(req.body))
    }
}

module.exports = new AccessController()