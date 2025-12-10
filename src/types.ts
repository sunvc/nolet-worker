export type APNsHeaders = {
	'apns-topic': string;
	'apns-id'?: string;
	'apns-collapse-id'?: string;
	'apns-priority'?: 5 | 10;
	'apns-expiration': number;
	'apns-push-type': 'alert' | 'background' | 'location' | 'voip' | 'complication' | 'fileprovider' | 'mdm' | 'liveactivity' | 'pushtotalk';
	authorization: string;
	'content-type': 'application/json';
};

export interface AlertPayload {
	title?: string;
	subtitle?: string;
	body?: string;
	'launch-image'?: string;
	'title-loc-key'?: string;
	'title-loc-args'?: string[];
	'subtitle-loc-key'?: string;
	'subtitle-loc-args'?: string[];
	'loc-key'?: string;
	'loc-args'?: string[];
}

export interface ApsPayload {
	aps: {
		alert?: AlertPayload;
		badge?: number;
		sound?: string | SoundObj;
		'thread-id'?: string;
		category?: string;
		'content-available'?: 1;
		'mutable-content'?: 1;
		'target-content-id'?: string;
		'interruption-level'?: 'passive' | 'active' | 'time-sensitive' | 'critical';
		'relevance-score'?: number;
		'filter-criteria'?: Record<string, any>;
		'stale-date'?: string;
		'content-state'?: string;
		timestamp?: string;
		event?: string;
		'dimissal-date'?: string;
		'attributes-type'?: string;
		attributes?: Record<string, any>;
	};
	[customKey: string]: any;
}

export type SoundObj = {
	critical: number;
	name: string;
	volume: number;
};

export type PushParameters = Record<string, string | number | boolean | undefined>;

export type RequestBodyMap = Record<string, unknown> & {
	devicekeys?: string | string[];
	devicekey?: string;
	body?: string;
	title?: string;
	subtitle?: string;
	markdown?: string;
};

export interface Database {
	countAll: () => Promise<number>;
	deviceTokenByKey: (key: string) => Promise<string | undefined>;
	saveDeviceTokenByKey: (key: string, token: string) => Promise<unknown | void>;
	saveAuthorizationToken: (token: string, time?: number) => Promise<unknown | void>;
	authorizationToken: () => Promise<string | undefined>;
}

export type ServerStats = {
	pid: {
		cpu: number;
		ram: number;
		conns: number;
	};
	os: {
		cpu: number;
		ram: number;
		total_ram: number;
		load_avg: number;
		conns: number;
	};
};
