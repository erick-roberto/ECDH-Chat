require('dotenv').config();

const isProduction = process.env.NODE_ENV === 'production';

const rawOrigins = process.env.CORS_ORIGIN || '';
const configuredOrigins = rawOrigins
    .split(',')
    .map(url => url.trim())
    .filter(Boolean);

const corsOrigin = isProduction
    ? configuredOrigins
    : function (origin, callback) {
          if (!origin || origin === 'null') {
              return callback(null, true);
          }

          const isLocal = /^(http:\/\/)?(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?$/.test(origin);
          const isPrivateIP = /^(http:\/\/)?(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+)(:\d+)?$/.test(origin);

          if (isLocal || isPrivateIP) {
              return callback(null, true);
          }

          callback(new Error('Origem bloqueada pela política de CORS local.'));
      };

module.exports = {
    isProduction,
    configuredOrigins,
    corsOrigin
};