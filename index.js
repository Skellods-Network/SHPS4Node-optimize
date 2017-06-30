'use strict';

const Result = require('rustify-js').Result;

module.exports = class Optimize {
    static init() {
        return Result.fromSuccess(new Optimize());
    }
};
