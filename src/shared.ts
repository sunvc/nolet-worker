import type { Database, APNsHeaders, AlertPayload, ApsPayload, PushParameters, RequestBodyMap, ServerStats } from './types';
import { IndexHtml, TOKEN_KEY, VERSION, BUILD, ARCH, COMMIT, TEAM_ID, AUTH_KEY_ID, TOPIC, APNS_HOST_NAME } from './static';

function jsonResponse(body: Record<string, unknown>) {
	return new Response(JSON.stringify({ ...body, timestamp: util.getTimestamp() }), {
		status: 200,
		headers: { 'content-type': 'application/json' },
	});
}

class Util {
	getTimestamp: () => number;
	base64ToArrayBuffer: (base64: string) => Uint8Array;
	newShortUUID: () => Promise<string>;
	constantTimeCompare: (a: string, b: string) => boolean;
	validateBasicAuth: (request: Request, basicAuth?: string) => boolean;
	randomServerStats: (totalRam?: number) => ServerStats;
	constructor() {
		this.getTimestamp = () => {
			return Math.floor(Date.now() / 1000);
		};

		this.base64ToArrayBuffer = (base64: string) => {
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
			const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(uuid));
			const hashArray = Array.from(new Uint8Array(hashBuffer));

			return btoa(String.fromCharCode(...hashArray))
				.replace(/[^a-zA-Z0-9]/g, '')
				.slice(0, 22);
		};

		this.constantTimeCompare = (a: string, b: string) => {
			if (typeof a !== 'string' || typeof b !== 'string') return false;
			if (a.length !== b.length) return false;
			let result = 0;
			for (let i = 0; i < a.length; i++) {
				result |= a.charCodeAt(i) ^ b.charCodeAt(i);
			}
			return result === 0;
		};

		this.validateBasicAuth = (request: Request, basicAuth?: string) => {
			if (basicAuth) {
				const authHeader = request.headers.get('Authorization');
				if (typeof authHeader !== 'string' || !authHeader.startsWith('Basic ')) return false;
				const received = authHeader.slice(6);
				const expected = btoa(`${basicAuth}`);
				return this.constantTimeCompare(received, expected);
			}
			return true;
		};

		this.randomServerStats = (totalRam?: number) => {
			return {
				pid: {
					cpu: Math.random() * 20,
					ram: Math.floor(Math.random() * 100 * 1024 * 1024),
					conns: Math.floor(Math.random() * 100),
				},
				os: {
					cpu: Math.random() * 50,
					ram: Math.floor(Math.random() * 10 * 1024 * 1024 * 1024),
					total_ram: totalRam || 32 * 1024 * 1024 * 1024,
					load_avg: Math.random() * 20,
					conns: Math.floor(Math.random() * 500),
				},
			};
		};
	}
}

class DatabaseKV implements Database {
	countAll: () => Promise<number>;
	deviceTokenByKey: (key: string) => Promise<string | undefined>;
	saveDeviceTokenByKey: (key: string, token: string) => Promise<void>;
	saveAuthorizationToken: (token: string, time?: number) => Promise<void>;
	authorizationToken: () => Promise<string | undefined>;
	constructor(env: Env) {
		const kvStorage = env.databaseKV;

		this.countAll = async () => {
			const count = (await kvStorage.list()).keys.length;
			return count;
		};

		this.deviceTokenByKey = async (key: string) => {
			const device_key = (key || '').replace(/[^a-zA-Z0-9]/g, '') || '_PLACE_HOLDER_';
			const deviceToken = await kvStorage.get(device_key);
			return deviceToken ?? undefined;
		};

		this.saveDeviceTokenByKey = async (key: string, token: string) => {
			const device_token = (token || '').replace(/[^a-z0-9]/g, '') || '';
			const deviceToken = await kvStorage.put(key, device_token);
			return await deviceToken;
		};

		this.saveAuthorizationToken = async (token: string, time?: number) => {
			const authToken = await kvStorage.put('_authToken_', token, {
				expirationTtl: 3000,
			});
			return await authToken;
		};

		this.authorizationToken = async () => {
			const v = await kvStorage.get('_authToken_');
			return v ?? undefined;
		};
	}
}

class DatabaseSQL implements Database {
	countAll: () => Promise<number>;
	deviceTokenByKey: (key: string) => Promise<string | undefined>;
	saveDeviceTokenByKey: (key: string, token: string) => Promise<unknown>;
	saveAuthorizationToken: (token: string, time?: number) => Promise<unknown>;
	authorizationToken: () => Promise<string | undefined>;
	constructor(env: Env) {
		const db = env.database;

		db.exec(
			'CREATE TABLE IF NOT EXISTS `devices` (`id` INTEGER PRIMARY KEY, `key` VARCHAR(255) NOT NULL, `token` VARCHAR(255) NOT NULL, UNIQUE (`key`))'
		);
		db.exec(
			'CREATE TABLE IF NOT EXISTS `authorization` (`id` INTEGER PRIMARY KEY, `token` VARCHAR(255) NOT NULL, `time` VARCHAR(255) NOT NULL)'
		);

		this.countAll = async () => {
			const query = 'SELECT COUNT(*) as rowCount FROM `devices`';
			const result = await db.prepare(query).run();
			return (result.results[0] || { rowCount: -1 }).rowCount as number;
		};

		this.deviceTokenByKey = async (key: string) => {
			const device_key = (key || '').replace(/[^a-zA-Z0-9]/g, '') || '_PLACE_HOLDER_';
			const query = 'SELECT `token` FROM `devices` WHERE `key` = ?';
			const result = await db.prepare(query).bind(device_key).run();
			return (result.results[0] || {}).token as string | undefined;
		};

		this.saveDeviceTokenByKey = async (key: string, token: string) => {
			const device_token = (token || '').replace(/[^a-z0-9]/g, '') || '';
			const query = 'INSERT OR REPLACE INTO `devices` (`key`, `token`) VALUES (?, ?)';
			const result = await db.prepare(query).bind(key, device_token).run();
			return result;
		};

		this.saveAuthorizationToken = async (token: string, time: number = util.getTimestamp()) => {
			const query = 'INSERT OR REPLACE INTO `authorization` (`id`, `token`, `time`) VALUES (1, ?, ?)';
			const result = await db.prepare(query).bind(token, time).run();
			return result;
		};

		this.authorizationToken = async () => {
			const query = 'SELECT `token`, `time` FROM `authorization` WHERE `id` = 1';
			const result = await db.prepare(query).run();
			if (result.results.length > 0) {
				const tokenTime = parseInt(result.results[0].time as string);
				const timeDifference = util.getTimestamp() - tokenTime;
				if (timeDifference <= 3000) {
					return result.results[0].token as string;
				}
			}
			return undefined;
		};
	}
}

class APNs {
	push: (deviceToken: string, headers: APNsHeaders, aps: ApsPayload) => Promise<Response>;
	constructor(db: Database) {
		const generateAuthToken = async () => {
			const privateKeyPEM = TOKEN_KEY.replace('-----BEGIN PRIVATE KEY-----', '')
				.replace('-----END PRIVATE KEY-----', '')
				.replace(/\s/g, '');
			const privateKeyArrayBuffer = util.base64ToArrayBuffer(privateKeyPEM);
			const privateKey = await crypto.subtle.importKey('pkcs8', privateKeyArrayBuffer, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
				'sign',
			]);
			const JWT_ISSUE_TIME = util.getTimestamp();
			const JWT_HEADER = btoa(JSON.stringify({ alg: 'ES256', kid: AUTH_KEY_ID }))
				.replace('+', '-')
				.replace('/', '_')
				.replace(/=+$/, '');
			const JWT_CLAIMS = btoa(JSON.stringify({ iss: TEAM_ID, iat: JWT_ISSUE_TIME }))
				.replace('+', '-')
				.replace('/', '_')
				.replace(/=+$/, '');
			const JWT_HEADER_CLAIMS = JWT_HEADER + '.' + JWT_CLAIMS;
			const jwtArray = new TextEncoder().encode(JWT_HEADER_CLAIMS);
			const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, jwtArray);
			const signatureArray = new Uint8Array(signature);
			const JWT_SIGNED_HEADER_CLAIMS = btoa(String.fromCharCode(...signatureArray))
				.replace('+', '-')
				.replace('/', '_')
				.replace(/=+$/, '');
			const AUTHENTICATION_TOKEN = JWT_HEADER_CLAIMS + '.' + JWT_SIGNED_HEADER_CLAIMS;

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

		this.push = async (deviceToken: string, headers: APNsHeaders, aps: ApsPayload) => {
			const AUTHENTICATION_TOKEN = await getAuthToken();

			const apnsPriority = headers['apns-priority'];
			return await fetch(`https://${APNS_HOST_NAME}/3/device/${deviceToken}`, {
				method: 'POST',
				headers: JSON.parse(
					JSON.stringify({
						'apns-topic': headers['apns-topic'] || TOPIC,
						'apns-id': headers['apns-id'] || undefined,
						'apns-collapse-id': headers['apns-collapse-id'] || undefined,
						'apns-priority': typeof apnsPriority === 'number' && apnsPriority > 0 ? apnsPriority : undefined,
						'apns-expiration': util.getTimestamp() + 86400,
						'apns-push-type': headers['apns-push-type'] || 'alert',
						authorization: `bearer ${AUTHENTICATION_TOKEN}`,
						'content-type': 'application/json',
					})
				),
				body: JSON.stringify(aps),
			});
		};
	}
}

class Handler {
	allowNewDevice: boolean;
	allowQueryNums: boolean;
	devices?: number;
	restore: (key?: string) => Promise<Response>;
	register: (parameters: PushParameters & { token?: string; key?: string }) => Promise<Response>;
	ping: (params?: URLSearchParams) => Promise<Response>;
	monitor: (params: URLSearchParams) => Promise<Response>;
	health: (params: URLSearchParams) => Promise<Response>;
	info: (params: URLSearchParams) => Promise<Response>;
	push: (parameters: PushParameters & { devicekey: string }) => Promise<Response>;
	constructor(db: Database, options: { allowNewDevice: boolean; allowQueryNums: boolean }) {
		this.allowNewDevice = options.allowNewDevice;
		this.allowQueryNums = options.allowQueryNums;

		this.restore = async (key?: string) => {
			if (key && (await db.deviceTokenByKey(key))) {
				return jsonResponse({ code: 200, message: 'success' });
			} else {
				return jsonResponse({ code: 400, message: 'device key is not exist' });
			}
		};

		this.register = async (parameters: PushParameters & { token?: string; key?: string }) => {
			const deviceToken = parameters.token as string | undefined;
			let key = parameters.key as string | undefined;
			if (!deviceToken) {
				return jsonResponse({ code: 400, message: 'device token is empty' });
			}
			if (!(key && (await db.deviceTokenByKey(key)))) {
				if (this.allowNewDevice) {
					key = await util.newShortUUID();
				} else {
					return jsonResponse({ code: 500, message: 'device registration failed: register disabled' });
				}
			}
			await db.saveDeviceTokenByKey(key, deviceToken);
			return jsonResponse({ code: 200, message: 'success', data: { key: key, token: deviceToken } });
		};

		this.ping = async (params?: URLSearchParams) => {
			return jsonResponse({ code: 200, message: 'pong' });
		};

		this.monitor = async (params?: URLSearchParams) => {
			return jsonResponse(util.randomServerStats(undefined));
		};

		this.health = async (params?: URLSearchParams) => {
			return new Response('OK', {
				status: 200,
				headers: { 'content-type': 'text/plain' },
			});
		};

		this.info = async (params?: URLSearchParams) => {
			if (this.allowQueryNums) {
				this.devices = await db.countAll();
			}
			return jsonResponse({ version: VERSION, build: BUILD, arch: ARCH, commit: COMMIT, devices: this.devices });
		};

		this.push = async (parameters: PushParameters & { devicekey: string }) => {
			const deviceToken = await db.deviceTokenByKey(parameters.devicekey);
			if (deviceToken === undefined) {
				return jsonResponse({
					code: 400,
					message: `failed to get device token: failed to get [${parameters.devicekey}] device token from database`,
				});
			}
			if (!deviceToken) {
				return jsonResponse({ code: 400, message: 'device token invalid' });
			}
			let title = parameters.title as string | undefined;
			let subtitle = parameters.subtitle as string | undefined;
			let markdown = parameters.markdown as string | undefined;
			let body = markdown || (parameters.body as string | undefined);
			let sound = parameters.sound as string | undefined;

			if (sound) {
				if (!sound.endsWith('.caf')) {
					sound += '.caf';
				}
			} else {
				sound = 'nolet.caf';
			}
			const group = parameters.group as string | undefined;
			const id = parameters.id as string | undefined;
			const _delete = !title && !subtitle && !body && id;
			const aps: ApsPayload = {
				aps: _delete
					? {
							'content-available': 1,
							'mutable-content': 1,
					  }
					: {
							alert: {
								title: title,
								subtitle: subtitle,
								body: !title && !subtitle && !body ? '-' : body,
								'launch-image': undefined,
								'title-loc-key': undefined,
								'title-loc-args': undefined,
								'subtitle-loc-key': undefined,
								'subtitle-loc-args': undefined,
								'loc-key': undefined,
								'loc-args': undefined,
							},
							badge: undefined,
							sound: sound,
							'thread-id': group,
							category: markdown ? 'markdown' : 'myNotificationCategory',
							'content-available': undefined,
							'mutable-content': 1,
							'target-content-id': id,
							'interruption-level': undefined,
							'relevance-score': undefined,
							'filter-criteria': undefined,
							'stale-date': undefined,
							'content-state': undefined,
							timestamp: undefined,
							event: undefined,
							'dimissal-date': undefined,
							'attributes-type': undefined,
							attributes: undefined,
					  },
			};
			const excludeKeys = ['title', 'subtitle', 'body', 'sound', 'md', 'markdown', 'text', 'message', 'content', 'data', 'devicekey'];
			for (const [key, value] of Object.entries(parameters)) {
				if (!excludeKeys.includes(key) && value) {
					aps[key] = value as unknown;
				}
			}
			const headers: APNsHeaders = {
				'apns-topic': '',
				'apns-id': undefined,
				'apns-collapse-id': id,
				'apns-priority': undefined,
				'apns-expiration': 0,
				authorization: '',
				'apns-push-type': _delete ? 'background' : 'alert',
				'content-type': 'application/json',
			};
			const apns = new APNs(db);
			const response = await apns.push(deviceToken, headers, aps);
			if (response.status === 200) {
				return jsonResponse({ code: 200, message: 'success' });
			} else {
				let message;
				const responseText = await response.text();
				try {
					message = JSON.parse(responseText).reason;
				} catch (err) {
					message = responseText;
				}
				if (response.status === 410 || (response.status === 400 && message.includes('BadDeviceToken'))) {
					await db.saveDeviceTokenByKey(parameters.devicekey, '');
				}
				return jsonResponse({ code: response.status, message: `push failed: ${message}` });
			}
		};
	}
}

async function handle(request: Request, env: Env, ctx: ExecutionContext, db: Database) {
	const allowNewDevice =
		env.ALLOW_NEW_DEVICE !== undefined ? (env.ALLOW_NEW_DEVICE === 'false' ? false : Boolean(env.ALLOW_NEW_DEVICE)) : true;
	const allowQueryNums =
		env.ALLOW_QUERY_NUMS !== undefined ? (env.ALLOW_QUERY_NUMS === 'false' ? false : Boolean(env.ALLOW_QUERY_NUMS)) : true;
	const rootPath = env.ROOT_PATH || '/';
	const basicAuth = env.BASIC_AUTH;

	const { searchParams, pathname, origin } = new URL(request.url);
	const handler = new Handler(db, { allowNewDevice, allowQueryNums });
	const realPathname = pathname.replace(new RegExp('^' + rootPath.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&')), '/');

	if (realPathname === '/logo.png' || realPathname === '/favicon.ico') {
		const png = await env.ASSETS.fetch(`${origin}/logo.png`);
		return new Response(png.body, {
			headers: {
				'Content-Type': 'image/png',
			},
		});
	}

	if (request.method.toUpperCase() === 'GET' && realPathname.startsWith('/register')) {
		const pathParts = realPathname.split('/').filter(Boolean);
		return handler.restore(pathParts[1]);
	}

	if (realPathname === '/') {
		return new Response(IndexHtml('', request.url), {
			status: 200,
			headers: { 'content-type': 'text/html; charset=utf-8' },
		});
	}

	switch (realPathname) {
		case '/register': {
			return handler.register(await request.json());
		}
		case '/ping': {
			return handler.ping(searchParams);
		}
		case '/monitor': {
			return handler.monitor(searchParams);
		}
		case '/health': {
			return handler.health(searchParams);
		}
		case '/info': {
			if (!util.validateBasicAuth(request, basicAuth)) {
				return jsonResponse({ code: 401, message: 'Unauthorized' });
			}
			return handler.info(searchParams);
		}
		default: {
			const pathParts = realPathname.split('/').filter(Boolean);

			if (pathParts.length >= 1) {
				if (!util.validateBasicAuth(request, basicAuth)) {
					return new Response('Unauthorized', {
						status: 401,
						headers: {
							'content-type': 'text/plain',
							'WWW-Authenticate': 'Basic',
						},
					});
				}
				const contentType = request.headers.get('content-type');
				let requestBody: RequestBodyMap = {};
				try {
					if (contentType && contentType.includes('application/json')) {
						requestBody = (await request.json()) as RequestBodyMap;
					} else if (contentType && contentType.includes('application/x-www-form-urlencoded')) {
						const formData = await request.formData();
						formData.forEach((value, key) => {
							requestBody[key] = value as unknown;
						});
					} else {
						searchParams.forEach((value, key) => {
							requestBody[key] = value;
						});

						switch (pathParts.length) {
							case 2:
								requestBody.body = pathParts[1];
								break;
							case 3:
								requestBody.title = pathParts[1];
								requestBody.body = pathParts[2];
								break;
							case 4:
								requestBody.title = pathParts[1];
								requestBody.subtitle = pathParts[2];
								requestBody.body = pathParts[3];
								break;
							default:
								return jsonResponse({ code: 404, message: `Cannot ${request.method} ${realPathname}` });
						}
					}

					let normalizeKeys = (obj: Record<string, unknown>): RequestBodyMap => {
						const newObj: RequestBodyMap = {};
						for (const [key, value] of Object.entries(obj)) {
							const newKey = key.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
							newObj[newKey] = value;
						}
						return newObj;
					};
					requestBody = normalizeKeys(requestBody);

					let body =
						(requestBody.body as string | undefined) ||
						(requestBody.message as string | undefined) ||
						(requestBody.content as string | undefined) ||
						(requestBody.data as string | undefined) ||
						(requestBody.text as string | undefined);

					if (body) requestBody.body = body;
					let markdown = (requestBody.md as string | undefined) || (requestBody.markdown as string | undefined) || undefined;
					if (markdown) requestBody.markdown = markdown;

					if (!contentType || !contentType.includes('application/json')) {
						try {
							['title', 'subtitle', 'body', 'markdown'].forEach((key) => {
								const val = requestBody[key];
								if (typeof val === 'string' && val) {
									requestBody[key] = decodeURIComponent(val.replace(/\+/g, ' '));
								}
							});
						} catch (error) {
							return jsonResponse({ code: 500, message: `URL parse failed: ${error}` });
						}
					}

					if (requestBody.devicekeys && typeof requestBody.devicekeys === 'string') {
						if (requestBody.devicekeys.startsWith('[') || requestBody.devicekeys.endsWith(']')) {
							requestBody.devicekeys = JSON.parse(requestBody.devicekeys);
						} else {
							requestBody.devicekeys = decodeURIComponent(requestBody.devicekeys)
								.trim()
								.split(',')
								.map((item) => item.replace(/"/g, '').trim())
								.filter(Boolean);
						}
					}
				} catch (error) {
					return jsonResponse({ code: 400, message: `request bind failed: ${error}` });
				}
				if (requestBody.devicekeys && Array.isArray(requestBody.devicekeys) && requestBody.devicekeys.length > 0) {
					return jsonResponse({
						code: 200,
						message: 'success',
						data: await Promise.all(
							requestBody.devicekeys.map(async (devicekey: string) => {
								if (!devicekey) {
									return { code: 400, message: 'device key is empty', key: devicekey };
								}
								const baseParams = { ...requestBody } as { devicekeys?: string | string[] } & PushParameters;
								delete baseParams.devicekeys;
								const response = await handler.push({ ...baseParams, devicekey } as PushParameters & { devicekey: string });
								const responseBody = (await response.json()) as { message?: string };
								return { code: response.status, message: responseBody.message, key: devicekey };
							})
						),
					});
				}
				if (realPathname != '/push') {
					requestBody.devicekey = pathParts[0];
				}
				if (!requestBody.devicekey) {
					return jsonResponse({ code: 400, message: 'device key is empty' });
				}
				const pushParams = { ...requestBody } as { devicekeys?: string | string[] } & (PushParameters & { devicekey: string });
				delete pushParams.devicekeys;
				return handler.push(pushParams);
			}
			return jsonResponse({ code: 404, message: `Cannot ${request.method} ${realPathname}` });
		}
	}
}

const util = new Util();

export { VERSION, BUILD, ARCH, COMMIT, util, DatabaseKV, DatabaseSQL, APNs };
export { handle };
