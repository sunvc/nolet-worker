export type APNsHeaders = Record<string, string | number | undefined>;
export type ApsPayload = Record<string, unknown>;
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
