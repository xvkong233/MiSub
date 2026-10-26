import { describe, it, expect } from 'vitest';
import { extractValidNodes, parseNodeList } from '../../functions/modules/utils/node-parser.js';
import {
    decodeV2raynNodeUrl,
    renameV2raynNodeUrl,
    getV2raynRemarks,
} from '../../functions/modules/utils/v2rayn-utils.js';
import { parseNodeInfo } from '../../functions/modules/utils/geo-utils.js';
import { isRealProxyNode } from '../../functions/services/subscription-service.js';
import { prependNodeName, addFlagEmoji } from '../../functions/utils/node-utils.js';
import { setNodeName } from '../../functions/utils/node-transformer.js';

/** 构造 v2rayn:// 链接（URL-Safe Base64，模拟 v2rayN 导出格式） */
function makeV2raynUrl(protocol, config) {
    const b64 = Buffer.from(JSON.stringify(config), 'utf-8')
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
    return `v2rayn://${protocol}/${b64}`;
}

const v2raynHysteria2 = makeV2raynUrl('hysteria2', {
    ConfigType: 7,
    ConfigVersion: 4,
    Remarks: 'US精品 hysteria2',
    Address: '156.238.228.228',
    Port: 8443,
    Password: 'secretpass',
});
const v2raynTuic = makeV2raynUrl('tuic', {
    ConfigType: 8,
    Remarks: 'US精品 tuic',
    Address: 'skk.moe',
    Port: 443,
});
const v2raynTrojan = makeV2raynUrl('trojan', {
    ConfigType: 6,
    Remarks: 'US精品 trojan',
    Address: '156.238.228.228',
    Port: 443,
});
const v2raynAnytls = makeV2raynUrl('anytls', {
    ConfigType: 11,
    Remarks: 'US精品 anytls',
    Address: '156.238.228.228',
    Port: 8880,
});
const v2raynNaiveHttp2 = makeV2raynUrl('naive', {
    ConfigType: 12,
    Remarks: 'US精品 naive http2',
    Address: '156.238.228.228',
    Port: 443,
});

// 模拟真实上游订阅（v2rayN UA 拿到的 base64 明文内容，含分隔线）
const plainUpstream = [
    '----------------------------',
    'vless://fd31c884-1cff-44f5-bebf-761b596f88ce@156.238.228.228:8881?encryption=none&flow=xtls-rprx-vision&security=reality#US精品%20xtls-reality',
    '----------------------------',
    v2raynHysteria2,
    '----------------------------',
    v2raynTuic,
    '----------------------------',
    '----------------------------',
    'ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206WDZtOFdRY2REdmV3T0pMWWF0eXJ4QT09@156.238.228.228:8885#US精品%20shadowsocks',
    '----------------------------',
    v2raynTrojan,
    '----------------------------',
    'vmess://eyJ2IjoiMiIsInBzIjoiVVPnsr7lk4Egdm1lc3Mtd3MiLCJhZGQiOiJza2subW9lIiwicG9ydCI6IjgwIiwiaWQiOiJmZDMxYzg4NC0xY2ZmLTQ0ZjUtYmViZi03NjFiNTk2Zjg4Y2UiLCJhaWQiOiIwIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsInRscyI6IiJ9',
    '----------------------------',
    'vless://fd31c884-1cff-44f5-bebf-761b596f88ce@skk.moe:443?encryption=none&security=tls&sni=xvkong.neujz.xyz&type=ws&host=xvkong.neujz.xyz#US精品%20vless-ws-tls',
    '----------------------------',
    v2raynAnytls,
    '----------------------------',
    v2raynNaiveHttp2,
].join('\n');

describe('v2rayn:// 分享格式透传', () => {
    describe('decodeV2raynNodeUrl', () => {
        it('应解析出内层协议与 ProfileItem 配置', () => {
            const decoded = decodeV2raynNodeUrl(v2raynHysteria2);
            expect(decoded).toBeTruthy();
            expect(decoded.protocol).toBe('hysteria2');
            expect(decoded.config.Remarks).toBe('US精品 hysteria2');
            expect(decoded.config.Address).toBe('156.238.228.228');
            expect(decoded.config.Port).toBe(8443);
        });

        it('非 v2rayn 链接应返回 null', () => {
            expect(decodeV2raynNodeUrl('vmess://YWJj')).toBeNull();
            expect(decodeV2raynNodeUrl('')).toBeNull();
            expect(decodeV2raynNodeUrl(null)).toBeNull();
        });
    });

    describe('extractValidNodes / parseNodeList', () => {
        it('base64 订阅中的 v2rayn:// 节点不应被丢弃', () => {
            const encoded = Buffer.from(plainUpstream, 'utf-8').toString('base64');
            const nodes = extractValidNodes(encoded);
            const v2raynNodes = nodes.filter((n) => n.startsWith('v2rayn://'));

            expect(v2raynNodes).toHaveLength(5);
            expect(nodes).toHaveLength(9);
        });

        it('parseNodeList 应保留 v2rayn 节点且 URL 原样透传', () => {
            const parsed = parseNodeList(plainUpstream);
            const hysteria2 = parsed.find((n) => n.url === v2raynHysteria2);

            expect(hysteria2).toBeTruthy();
            expect(hysteria2.protocol).toBe('hysteria2');
            expect(hysteria2.name).toBe('US精品 hysteria2');
            expect(hysteria2.server).toBe('156.238.228.228');
            expect(hysteria2.port).toBe('8443');
            expect(parsed).toHaveLength(9);
        });

        it('载荷损坏的 v2rayn 节点仍应保留（不丢弃）', () => {
            const parsed = parseNodeList('v2rayn://hysteria2/!!!invalid-base64!!!');
            expect(parsed).toHaveLength(1);
            expect(parsed[0].url).toBe('v2rayn://hysteria2/!!!invalid-base64!!!');
        });
    });

    describe('parseNodeInfo', () => {
        it('v2rayn 节点应上报内层协议与 Remarks 名称', () => {
            const info = parseNodeInfo(v2raynHysteria2);
            expect(info.protocol).toBe('hysteria2');
            expect(info.name).toBe('US精品 hysteria2');
            expect(info.region).toBe('美国');
            expect(info.url).toBe(v2raynHysteria2);
        });
    });

    describe('isRealProxyNode', () => {
        it('v2rayn:// 应被认定为真实节点', () => {
            expect(isRealProxyNode(v2raynHysteria2)).toBe(true);
        });
    });

    describe('改名链路不得破坏载荷', () => {
        it('prependNodeName 应改写 Remarks 而非拼接 # 片段', () => {
            const prefixed = prependNodeName(v2raynHysteria2, '机场A');
            expect(prefixed).not.toContain('#');
            expect(getV2raynRemarks(prefixed)).toBe('机场A - US精品 hysteria2');
        });

        it('setNodeName 即使传入内层协议也应改写 Remarks（URL 判定优先）', () => {
            const renamed = setNodeName(v2raynHysteria2, 'hysteria2', '新名字');
            expect(renamed).not.toContain('#');
            expect(getV2raynRemarks(renamed)).toBe('新名字');
        });

        it('addFlagEmoji 应把 emoji 写入 Remarks 而不是拼接 # 片段', () => {
            const withEmoji = addFlagEmoji(v2raynHysteria2);
            expect(withEmoji).not.toContain('#');
            expect(getV2raynRemarks(withEmoji)).toBe('🇺🇸 US精品 hysteria2');
        });

        it('renameV2raynNodeUrl 对损坏载荷应原样返回', () => {
            const bad = 'v2rayn://hysteria2/!!!invalid-base64!!!';
            expect(renameV2raynNodeUrl(bad, '新名字')).toBe(bad);
        });
    });
});
