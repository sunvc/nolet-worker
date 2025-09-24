export default {
  async fetch(request, env, ctx) {
    return await handleRequest(request, env, ctx);
  },
};

async function handleRequest(request, env, ctx) {
  const allowNewDevice =
    env.ALLOW_NEW_DEVICE !== undefined
      ? env.ALLOW_NEW_DEVICE === "false"
        ? false
        : Boolean(env.ALLOW_NEW_DEVICE)
      : true;
  const allowQueryNums =
    env.ALLOW_QUERY_NUMS !== undefined
      ? env.ALLOW_QUERY_NUMS === "false"
        ? false
        : Boolean(env.ALLOW_QUERY_NUMS)
      : true;
  const rootPath = env.ROOT_PATH || "/";
  const basicAuth = env.BASIC_AUTH;

  const { searchParams, pathname } = new URL(request.url);
  const handler = new Handler(env, { allowNewDevice, allowQueryNums });
  const realPathname = pathname.replace(
    new RegExp("^" + rootPath.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&")),
    "/"
  );

  if (realPathname.startsWith("/register/")) {
    const pathParts = realPathname.split("/");
    if (pathParts[2]) {
      return handler.restore(pathParts[2]);
    }
  }

  switch (realPathname) {
    case "/register": {
      return handler.register(await request.json());
    }
    case "/ping": {
      return handler.ping(searchParams);
    }
    case "/monitor": {
      return handler.monitor(searchParams);
    }
    case "/health": {
      return handler.health(searchParams);
    }
    case "/info": {
      if (!util.validateBasicAuth(request, basicAuth)) {
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            "content-type": "text/plain",
            "WWW-Authenticate": "Basic",
          },
        });
      }
      return handler.info(searchParams);
    }
    default: {
      const pathParts = realPathname.split("/");

      if (pathParts[1]) {
        if (!util.validateBasicAuth(request, basicAuth)) {
          return new Response("Unauthorized", {
            status: 401,
            headers: {
              "content-type": "text/plain",
              "WWW-Authenticate": "Basic",
            },
          });
        }

        const contentType = request.headers.get("content-type");
        let requestBody = {};

        try {
          if (contentType && contentType.includes("application/json")) {
            requestBody = await request.json();
          } else if (
            contentType &&
            contentType.includes("application/x-www-form-urlencoded")
          ) {
            const formData = await request.formData();
            formData.forEach((value, key) => {
              requestBody[key] = value;
            });
          } else {
            searchParams.forEach((value, key) => {
              requestBody[key] = value;
            });

            if (pathParts.length === 3) {
              requestBody.body = pathParts[2];
            } else if (pathParts.length === 4) {
              requestBody.title = pathParts[2];
              requestBody.body = pathParts[3];
            } else if (pathParts.length === 5) {
              requestBody.title = pathParts[2];
              requestBody.subtitle = pathParts[3];
              requestBody.body = pathParts[4];
            } else if (pathParts.length > 5) {
              return new Response(
                JSON.stringify({
                  code: 404,
                  message: `Cannot ${request.method} ${realPathname}`,
                  timestamp: util.getTimestamp(),
                }),
                {
                  status: 404,
                  headers: {
                    "content-type": "application/json",
                  },
                }
              );
            }
          }
          let normalizeKeys = (obj) => {
            const newObj = {};
            for (const [key, value] of Object.entries(obj)) {
              // 转小写，替换掉 - 和 _
              const newKey = key.toLowerCase().replace(/[-_]/g, "");
              newObj[newKey] = value;
            }
            return newObj;
          };

          requestBody = normalizeKeys(requestBody);

          if (
            requestBody.devicekeys &&
            typeof requestBody.devicekeys === "string"
          ) {
            if (
              requestBody.devicekeys.startsWith("[") ||
              requestBody.devicekeys.endsWith("]")
            ) {
              requestBody.devicekeys = JSON.parse(requestBody.devicekeys);
            } else {
              requestBody.devicekeys = decodeURIComponent(
                requestBody.devicekeys
              )
                .trim()
                .split(",")
                .map((item) => item.replace(/"/g, "").trim());
            }

            if (typeof requestBody.devicekeys === "string") {
              requestBody.devicekeys = [requestBody.devicekeys];
            }
          }
        } catch (error) {
          return new Response(
            JSON.stringify({
              code: 400,
              message: `request bind failed: ${error}`,
              timestamp: util.getTimestamp(),
            }),
            {
              status: 400,
              headers: {
                "content-type": "application/json",
              },
            }
          );
        }

        if (requestBody.devicekeys && requestBody.devicekeys.length > 0) {
          return new Response(
            JSON.stringify({
              code: 200,
              message: "success",
              data: await Promise.all(
                requestBody.devicekeys.map(async (devicekey) => {
                  if (!devicekey) {
                    return {
                      code: 400,
                      message: "device key is empty",
                      key: devicekey,
                    };
                  }

                  const response = await handler.push({
                    ...requestBody,
                    devicekey,
                  });
                  const responseBody = await response.json();
                  return {
                    code: response.status,
                    message: responseBody.message,
                    key: devicekey,
                  };
                })
              ),
              timestamp: util.getTimestamp(),
            }),
            {
              status: 200,
              headers: {
                "content-type": "application/json",
              },
            }
          );
        }

        if (realPathname != "/push") {
          requestBody.devicekey = pathParts[1];
        }

        if (!requestBody.devicekey) {
          return new Response(
            JSON.stringify({
              code: 400,
              message: "device key is empty",
              timestamp: util.getTimestamp(),
            }),
            {
              status: 400,
              headers: {
                "content-type": "application/json",
              },
            }
          );
        }

        return handler.push(requestBody);
      }

      return new Response(
        JSON.stringify({
          code: 404,
          message: `Cannot ${request.method} ${realPathname}`,
          timestamp: util.getTimestamp(),
        }),
        {
          status: 404,
          headers: {
            "content-type": "application/json",
          },
        }
      );
    }
  }
}

class Handler {
  constructor(env, options) {
    this.version = "v0.0.1";
    this.build = "2025-09-20 16:01:13";
    this.arch = "js";
    this.commit = "2bec695dff5d3c71559ac61088a970ad0de59b48";
    this.allowNewDevice = options.allowNewDevice;
    this.allowQueryNums = options.allowQueryNums;
    const db = new Database(env);

    this.restore = async (key) => {
      if (await db.deviceTokenByKey(key)) {
        return new Response(
          JSON.stringify({
            code: 200,
            message: "success",
            timestamp: util.getTimestamp(),
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
            },
          }
        );
      } else {
        return new Response(
          JSON.stringify({
            code: 400,
            message: "device key is not exist",
            timestamp: util.getTimestamp(),
          }),
          {
            status: 400,
            headers: {
              "content-type": "application/json",
            },
          }
        );
      }
    }

    this.register = async (parameters) => {
      const deviceToken = parameters.token;
      let key = parameters.key;
      if (!deviceToken) {
        return new Response(
          JSON.stringify({
            code: 400,
            message: "device token is empty",
            timestamp: util.getTimestamp(),
          }),
          {
            status: 400,
            headers: {
              "content-type": "application/json",
            },
          }
        );
      }

      if (!(key && (await db.deviceTokenByKey(key)))) {
        if (this.allowNewDevice) {
          key = await util.newShortUUID();
        } else {
          return new Response(
            JSON.stringify({
              code: 500,
              message: "device registration failed: register disabled",
            }),
            {
              status: 500,
              headers: {
                "content-type": "application/json",
              },
            }
          );
        }
      }

      await db.saveDeviceTokenByKey(key, deviceToken);

      return new Response(
        JSON.stringify({
          code: 200,
          message: "success",
          timestamp: util.getTimestamp(),
          data: {
            key: key,
            token: deviceToken,
          },
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        }
      );
    };

    this.ping = async (parameters) => {
      return new Response(
        JSON.stringify({
          code: 200,
          message: "pong",
          timestamp: util.getTimestamp(),
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        }
      );
    };

    this.monitor = async (parameters) => {
      return new Response(JSON.stringify(util.randomServerStats()), {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      });
    };

    this.health = async (parameters) => {
      return new Response("OK", {
        status: 200,
        headers: {
          "content-type": "text/plain",
        },
      });
    };

    this.info = async (parameters) => {
      if (this.allowQueryNums) {
        this.devices = await db.countAll();
      }

      return new Response(
        JSON.stringify({
          version: this.version,
          build: this.build,
          arch: this.arch,
          commit: this.commit,
          devices: this.devices,
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        }
      );
    };

    this.push = async (parameters) => {
      const deviceToken = await db.deviceTokenByKey(parameters.devicekey);

      if (deviceToken === undefined) {
        return new Response(
          JSON.stringify({
            code: 400,
            message: `failed to get device token: failed to get [${parameters.devicekey}] device token from database`,
            timestamp: util.getTimestamp(),
          }),
          {
            status: 400,
            headers: {
              "content-type": "application/json",
            },
          }
        );
      }

      if (!deviceToken) {
        return new Response(
          JSON.stringify({
            code: 400,
            message: "device token invalid",
            timestamp: util.getTimestamp(),
          }),
          {
            status: 400,
            headers: {
              "content-type": "application/json",
            },
          }
        );
      }

      let title = parameters.title || undefined;
      let subtitle = parameters.subtitle || undefined;
      let body =
        parameters.body ||
        parameters.message ||
        parameters.content ||
        parameters.data ||
        parameters.text ||
        undefined;
      let markdown = parameters.md || parameters.markdown || undefined;
      try {
        if (title) {
          title = decodeURIComponent(title.replaceAll("\\+", "%20"));
        }

        if (subtitle) {
          subtitle = decodeURIComponent(subtitle.replaceAll("\\+", "%20"));
        }

        if (body) {
          body = decodeURIComponent(body.replaceAll("\\+", "%20"));
        }

        if (markdown) {
          body = decodeURIComponent(markdown.replaceAll("\\+", "%20"));
        }
      } catch (error) {
        return new Response(
          JSON.stringify({
            code: 500,
            meaasge: `url path parse failed: ${error}`,
            timestamp: util.getTimestamp(),
          }),
          {
            status: 500,
            headers: {
              "content-type": "application/json",
            },
          }
        );
      }

      let sound = parameters.sound || undefined;
      if (sound) {
        if (!sound.endsWith(".caf")) {
          sound += ".caf";
        }
      } else {
        sound = "1107";
      }

      const group = parameters.group || undefined;
      const id = parameters.id || undefined;
      const _delete = !title && !subtitle && !body && id;
      // https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification
      const aps = {
        aps: _delete
          ? {
            "content-available": 1,
            "mutable-content": 1,
          }
          : {
            alert: {
              title: title,
              subtitle: subtitle,
              body: !title && !subtitle && !body ? "Empty Message" : body,
              "launch-image": undefined,
              "title-loc-key": undefined,
              "title-loc-args": undefined,
              "subtitle-loc-key": undefined,
              "subtitle-loc-args": undefined,
              "loc-key": undefined,
              "loc-args": undefined,
            },
            badge: undefined,
            sound: sound,
            "thread-id": group,
            category: markdown ? "markdown" : "myNotificationCategory",
            "content-available": undefined,
            "mutable-content": 1,
            "target-content-id": id,
            "interruption-level": undefined,
            "relevance-score": undefined,
            "filter-criteria": undefined,
            "stale-date": undefined,
            "content-state": undefined,
            timestamp: undefined,
            event: undefined,
            "dimissal-date": undefined,
            "attributes-type": undefined,
            attributes: undefined,
          },
      };

      const excludeKeys = [
        "title",
        "subtitle",
        "body",
        "sound",
        "md",
        "markdown",
        "text",
        "message",
        "content",
        "data",
        "devicekey",
      ];
      for (const [key, value] of Object.entries(parameters)) {
        if (!excludeKeys.includes(key) && value) {
          aps[key] = value;
        }
      }

      const headers = {
        "apns-topic": undefined,
        "apns-id": undefined,
        "apns-collapse-id": id,
        "apns-priority": undefined,
        "apns-expiration": undefined,
        "apns-push-type": _delete ? "background" : "alert",
      };

      const apns = new APNs(db);
      const response = await apns.push(deviceToken, headers, aps);

      if (response.status === 200) {
        return new Response(
          JSON.stringify({
            code: 200,
            message: "success",
            timestamp: util.getTimestamp(),
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
            },
          }
        );
      } else {
        let message;
        const responseText = await response.text();

        try {
          message = JSON.parse(responseText).reason;
        } catch (err) {
          message = responseText;
        }

        if (
          response.status === 410 ||
          (response.status === 400 && message.includes("BadDeviceToken"))
        ) {
          await db.saveDeviceTokenByKey(parameters.devicekey, "");
        }

        return new Response(
          JSON.stringify({
            code: response.status,
            message: `push failed: ${message}`,
            timestamp: util.getTimestamp(),
          }),
          {
            status: response.status,
            headers: {
              "content-type": "application/json",
            },
          }
        );
      }
    };
  }
}

class APNs {
  constructor(db) {
    const generateAuthToken = async () => {
      const TOKEN_KEY = `
            -----BEGIN PRIVATE KEY-----
            MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgvjopbchDpzJNojnc
            o7ErdZQFZM7Qxho6m61gqZuGVRigCgYIKoZIzj0DAQehRANCAAQ8ReU0fBNg+sA+
            ZdDf3w+8FRQxFBKSD/Opt7n3tmtnmnl9Vrtw/nUXX4ldasxA2gErXR4YbEL9Z+uJ
            REJP/5bp
            -----END PRIVATE KEY-----
            `;

      // Parse private key
      const privateKeyPEM = TOKEN_KEY.replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace(/\s/g, "");
      // Decode private key
      const privateKeyArrayBuffer = util.base64ToArrayBuffer(privateKeyPEM);
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyArrayBuffer,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
      );
      const TEAM_ID = "FUWV6U942Q";
      const AUTH_KEY_ID = "BNY5GUGV38";
      // Generate the JWT token
      const JWT_ISSUE_TIME = util.getTimestamp();
      const JWT_HEADER = btoa(
        JSON.stringify({ alg: "ES256", kid: AUTH_KEY_ID })
      )
        .replace("+", "-")
        .replace("/", "_")
        .replace(/=+$/, "");
      const JWT_CLAIMS = btoa(
        JSON.stringify({ iss: TEAM_ID, iat: JWT_ISSUE_TIME })
      )
        .replace("+", "-")
        .replace("/", "_")
        .replace(/=+$/, "");
      const JWT_HEADER_CLAIMS = JWT_HEADER + "." + JWT_CLAIMS;
      // Sign
      const jwtArray = new TextEncoder().encode(JWT_HEADER_CLAIMS);
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        jwtArray
      );
      const signatureArray = new Uint8Array(signature);
      const JWT_SIGNED_HEADER_CLAIMS = btoa(
        String.fromCharCode(...signatureArray)
      )
        .replace("+", "-")
        .replace("/", "_")
        .replace(/=+$/, "");
      const AUTHENTICATION_TOKEN =
        JWT_HEADER_CLAIMS + "." + JWT_SIGNED_HEADER_CLAIMS;

      return AUTHENTICATION_TOKEN;
    };

    const getAuthToken = async () => {
      let authToken = await db.authorizationToken();

      if (authToken) {
        return await authToken;
      }

      authToken = await generateAuthToken();
      await db.saveAuthorizationToken(authToken, util.getTimestamp());

      return authToken;
    };

    this.push = async (deviceToken, headers, aps) => {
      const TOPIC = "me.uuneo.Meoworld";
      const APNS_HOST_NAME = "api.push.apple.com";
      const AUTHENTICATION_TOKEN = await getAuthToken();

      return await fetch(`https://${APNS_HOST_NAME}/3/device/${deviceToken}`, {
        method: "POST",
        headers: JSON.parse(
          JSON.stringify({
            "apns-topic": headers["apns-topic"] || TOPIC,
            "apns-id": headers["apns-id"] || undefined,
            "apns-collapse-id": headers["apns-collapse-id"] || undefined,
            "apns-priority":
              headers["apns-priority"] > 0
                ? headers["apns-priority"]
                : undefined,
            "apns-expiration": util.getTimestamp() + 86400,
            "apns-push-type": headers["apns-push-type"] || "alert",
            authorization: `bearer ${AUTHENTICATION_TOKEN}`,
            "content-type": "application/json",
          })
        ),
        body: JSON.stringify(aps),
      });
    };
  }
}

class Database {
  constructor(env) {
    const db = env.database;

    db.exec(
      "CREATE TABLE IF NOT EXISTS `devices` (`id` INTEGER PRIMARY KEY, `key` VARCHAR(255) NOT NULL, `token` VARCHAR(255) NOT NULL, UNIQUE (`key`))"
    );
    db.exec(
      "CREATE TABLE IF NOT EXISTS `authorization` (`id` INTEGER PRIMARY KEY, `token` VARCHAR(255) NOT NULL, `time` VARCHAR(255) NOT NULL)"
    );

    this.countAll = async () => {
      const query = "SELECT COUNT(*) as rowCount FROM `devices`";
      const result = await db.prepare(query).run();

      return (result.results[0] || { rowCount: -1 }).rowCount;
    };

    this.deviceTokenByKey = async (key) => {
      const device_key =
        (key || "").replace(/[^a-zA-Z0-9]/g, "") || "_PLACE_HOLDER_";
      const query = "SELECT `token` FROM `devices` WHERE `key` = ?";
      const result = await db.prepare(query).bind(device_key).run();

      return (result.results[0] || {}).token;
    };

    this.saveDeviceTokenByKey = async (key, token) => {
      const device_token = (token || "").replace(/[^a-z0-9]/g, "") || "";
      const query =
        "INSERT OR REPLACE INTO `devices` (`key`, `token`) VALUES (?, ?)";
      const result = await db.prepare(query).bind(key, device_token).run();

      return result;
    };

    this.saveAuthorizationToken = async (token) => {
      const query =
        "INSERT OR REPLACE INTO `authorization` (`id`, `token`, `time`) VALUES (1, ?, ?)";
      const result = await db
        .prepare(query)
        .bind(token, util.getTimestamp())
        .run();

      return result;
    };

    this.authorizationToken = async () => {
      const query =
        "SELECT `token`, `time` FROM `authorization` WHERE `id` = 1";
      const result = await db.prepare(query).run();

      if (result.results.length > 0) {
        const tokenTime = parseInt(result.results[0].time);
        const timeDifference = util.getTimestamp() - tokenTime;

        if (timeDifference <= 3000) {
          return result.results[0].token;
        }
      }

      return undefined;
    };
  }
}

class Util {
  constructor() {
    this.getTimestamp = () => {
      return Math.floor(Date.now() / 1000);
    };

    this.base64ToArrayBuffer = (base64) => {
      const binaryString = atob(base64);
      const length = binaryString.length;
      const buffer = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        buffer[i] = binaryString.charCodeAt(i);
      }
      return buffer;
    };

    this.newShortUUID = async () => {
      const uuid = crypto.randomUUID();
      const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(uuid)
      );
      const hashArray = Array.from(new Uint8Array(hashBuffer));

      return btoa(String.fromCharCode(...hashArray))
        .replace(/[^a-zA-Z0-9]/g, "")
        .slice(0, 22);
    };

    this.constantTimeCompare = (a, b) => {
      if (typeof a !== "string" || typeof b !== "string") return false;
      if (a.length !== b.length) return false;
      let result = 0;
      for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
      }
      return result === 0;
    };

    this.validateBasicAuth = (request, basicAuth) => {
      if (basicAuth) {
        const authHeader = request.headers.get("Authorization");
        if (typeof authHeader !== "string" || !authHeader.startsWith("Basic "))
          return false;
        const received = authHeader.slice(6); // 去掉 'Basic '
        const expected = btoa(`${basicAuth}`);
        return this.constantTimeCompare(received, expected);
      }
      return true;
    };

    this.randomServerStats = () => {
      return {
        pid: {
          cpu: Math.random() * 20, // %
          ram: Math.floor(Math.random() * 100 * 1024 * 1024), // bytes
          conns: Math.floor(Math.random() * 100),
        },
        os: {
          cpu: Math.random() * 50, // %
          ram: Math.floor(Math.random() * 10 * 1024 * 1024 * 1024), // bytes
          total_ram: 32 * 1024 * 1024 * 1024,
          load_avg: Math.random() * 20,
          conns: Math.floor(Math.random() * 500),
        },
      };
    };
  }
}

const util = new Util();
