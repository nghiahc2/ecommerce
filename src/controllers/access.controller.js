"use strict";

const { CREATED, SuccessResponse } = require("../core/success.response");
const AccessService = require("../services/access.service");

class AccessController {
  logout = async (req, res, next) => {
    new SuccessResponse({
      message: "Logout success!",
      metadata: await AccessService.logout(req.keyStore),
    }).send(res);
  };

  login = async (req, res, next) => {
    new SuccessResponse({
      metadata: await AccessService.login(req.body),
    }).send(res);
  };

  signUp = async (req, res, next) => {
    new CREATED({
      message: "Registered!",
      metadata: await AccessService.signUp(req.body),
      options: {
        limits: 10,
      },
    }).send(res);
    //return res.status(201).json(await AccessService.signUp(req.body))
  };
}

module.exports = new AccessController();
