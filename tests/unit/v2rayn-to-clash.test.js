import { describe, it, expect } from 'vitest';
import { urlToClashProxy, urlsToClashProxies } from '../../functions/utils/url-to-clash.js';

/** 构造 v2rayn:// 链接（URL-Safe Base64，模拟 v2rayN 导出格式） */
function makeV2raynUrl(protocol, config) {
    const b64 = Buffer.from(JSON.stringify(config), 'utf-8')
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
    return `v2rayn://${protocol}/${b64}`;
}

// 依据真实上游载荷结构构造的样例（凭据为合成值）
const hysteria2Cfg = {
    ConfigType: 7,
    ConfigVersion: 4,
    Remarks: '🇯🇵 test hysteria2',
    Address: '198.51.100.10',
    Port: 8882,
    Password: 'pass-hy2',
    StreamSecurity: 'tls',
    AllowInsecure: 'false',
    Sni: 'example.com',
    ProtoExtraObj: { UpMbps: 200, DownMbps: 1000 },
};
const tuicCfg = {
    ConfigType: 8,
    CoreType: 24,
    Remarks: '🇯🇵 test tuic',
    Address: '198.51.100.10',
    Port: 8883,
    Password: 'pass-tuic',
    Username: '0d0c6a15-6d1e-4c1b-9db1-2b1f0d3a4c55',
    StreamSecurity: 'tls',
    Sni: 'example.com',
    Alpn: 'h3',
    ProtoExtraObj: { CongestionControl: 'bbr' },
};
const trojanCfg = {
    ConfigType: 6,
    Remarks: '🇯🇵 test trojan',
    Address: '198.51.100.10',
    Port: 8886,
    Password: 'pass-trojan',
    Network: 'raw',
    StreamSecurity: 'tls',
    Sni: 'example.com',
};
const vlessRealityCfg = {
    ConfigType: 5,
    Remarks: '🇯🇵 test h2-reality',
    Address: '198.51.100.10',
    Port: 8889,
    Password: '0d0c6a15-6d1e-4c1b-9db1-2b1f0d3a4c55',
    Network: 'raw',
    StreamSecurity: 'reality',
    Sni: 'example.com',
    Fingerprint: 'chrome',
    PublicKey: 'pub-key-base64url',
};
const anytlsCfg = {
    ConfigType: 11,
    Remarks: '🇯🇵 test anytls',
    Address: '198.51.100.10',
    Port: 8891,
    Password: 'pass-anytls',
    StreamSecurity: 'tls',
    Sni: 'example.com',
};
const naiveCfg = {
    ConfigType: 12,
    Remarks: '🇯🇵 test naive',
    Address: '198.51.100.10',
    Port: 8892,
    Password: 'pass-naive',
    Username: 'user-naive',
    StreamSecurity: 'tls',
    Sni: 'example.com',
};

describe('v2rayn:// → Clash (mihomo) 转换', () => {
    it('hysteria2：password/auth/sni/上下行带宽', () => {
        const p = urlToClashProxy(makeV2raynUrl('hysteria2', hysteria2Cfg));
        expect(p.type).toBe('hysteria2');
        expect(p.server).toBe('198.51.100.10');
        expect(p.port).toBe(8882);
        expect(p.password).toBe('pass-hy2');
        expect(p.auth).toBe('pass-hy2');
        expect(p.sni).toBe('example.com');
        expect(p.up).toBe('200 Mbps');
        expect(p.down).toBe('1000 Mbps');
    });

    it('tuic：uuid/password/alpn/拥塞控制', () => {
        const p = urlToClashProxy(makeV2raynUrl('tuic', tuicCfg));
        expect(p.type).toBe('tuic');
        expect(p.uuid).toBe('0d0c6a15-6d1e-4c1b-9db1-2b1f0d3a4c55');
        expect(p.password).toBe('pass-tuic');
        expect(p.alpn).toEqual(['h3']);
        expect(p['congestion-controller']).toBe('bbr');
        expect(p.udp).toBe(true);
    });

    it('trojan：password/sni，Network=raw 不输出 network 字段', () => {
        const p = urlToClashProxy(makeV2raynUrl('trojan', trojanCfg));
        expect(p.type).toBe('trojan');
        expect(p.password).toBe('pass-trojan');
        expect(p.sni).toBe('example.com');
        expect(p.network).toBeUndefined();
    });

    it('vless reality：uuid/tls/reality-opts/client-fingerprint', () => {
        const p = urlToClashProxy(makeV2raynUrl('vless', vlessRealityCfg));
        expect(p.type).toBe('vless');
        expect(p.uuid).toBe('0d0c6a15-6d1e-4c1b-9db1-2b1f0d3a4c55');
        expect(p.tls).toBe(true);
        expect(p['reality-opts']['public-key']).toBe('pub-key-base64url');
        expect(p['client-fingerprint']).toBe('chrome');
        expect(p.servername).toBe('example.com');
    });

    it('anytls：password/sni', () => {
        const p = urlToClashProxy(makeV2raynUrl('anytls', anytlsCfg));
        expect(p.type).toBe('anytls');
        expect(p.password).toBe('pass-anytls');
        expect(p.sni).toBe('example.com');
    });

    it('自签证书载荷应输出 skip-cert-verify（mihomo 无法内嵌 PEM）', () => {
        const withCert = {
            ...hysteria2Cfg,
            AllowInsecure: 'false',
            Cert: '-----BEGIN CERTIFICATE-----',
        };
        const p = urlToClashProxy(makeV2raynUrl('hysteria2', withCert));
        expect(p['skip-cert-verify']).toBe(true);

        const insecure = { ...hysteria2Cfg, AllowInsecure: 'true' };
        const p2 = urlToClashProxy(makeV2raynUrl('hysteria2', insecure));
        expect(p2['skip-cert-verify']).toBe(true);
    });

    it('naive 及未知协议返回 null（mihomo 不支持）', () => {
        expect(urlToClashProxy(makeV2raynUrl('naive', naiveCfg))).toBeNull();
        expect(urlToClashProxy(makeV2raynUrl('unknown-proto', hysteria2Cfg))).toBeNull();
    });

    it('批量转换：5 个可转换 + naive 被过滤', () => {
        const urls = [
            makeV2raynUrl('hysteria2', hysteria2Cfg),
            makeV2raynUrl('tuic', tuicCfg),
            makeV2raynUrl('trojan', trojanCfg),
            makeV2raynUrl('vless', vlessRealityCfg),
            makeV2raynUrl('anytls', anytlsCfg),
            makeV2raynUrl('naive', naiveCfg),
        ];
        const proxies = urlsToClashProxies(urls);
        expect(proxies).toHaveLength(5);
        expect(proxies.map((p) => p.type).sort()).toEqual([
            'anytls',
            'hysteria2',
            'trojan',
            'tuic',
            'vless',
        ]);
    });
});
