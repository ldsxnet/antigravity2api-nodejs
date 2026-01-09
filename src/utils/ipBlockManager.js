import fs from 'fs/promises';
import path from 'path';
import { getDataDir } from './paths.js';
import logger from './logger.js';

const BLOCKLIST_FILE = 'ip-blocklist.json';
const TEMP_BLOCK_DURATION = 60 * 60 * 1000; // 1小时
const MAX_VIOLATIONS_BEFORE_TEMP_BLOCK = 20; // 20次违规触发临时封禁 (稍微放宽一点，避免誤伤)
const MAX_TEMP_BLOCKS_BEFORE_PERMANENT = 3; // 3次临时封禁触发永久封禁
const VIOLATION_WINDOW = 60 * 1000; // 1分钟内的违规计数窗口

// 本地白名单 IP
const WHITELISTED_IPS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1', 'localhost']);

class IpBlockManager {
  constructor() {
    this.filePath = null;
    this.data = {
      blocked_ips: {}
    };
    this.initialized = false;
    this.savePromise = Promise.resolve();
  }

  isWhitelisted(ip) {
    if (!ip) return false;
    return WHITELISTED_IPS.has(ip) || ip.startsWith('127.');
  }

  async init() {
    if (this.initialized) return;
    this.filePath = path.join(getDataDir(), BLOCKLIST_FILE);
    await this.load();
    this.initialized = true;
  }

  async load() {
    try {
      // 确保目录存在
      await fs.mkdir(path.dirname(this.filePath), { recursive: true });
      
      try {
        const content = await fs.readFile(this.filePath, 'utf8');
        this.data = JSON.parse(content);
      } catch (e) {
        if (e.code !== 'ENOENT') {
          logger.error('加载封禁列表失败:', e.message);
        }
        // 文件不存在则使用默认值
        this.data = { blocked_ips: {} };
      }
    } catch (e) {
      logger.error('初始化封禁管理器失败:', e.message);
    }
  }

  async save() {
    // 串行写入防止冲突
    this.savePromise = this.savePromise.then(async () => {
      try {
        await fs.writeFile(this.filePath, JSON.stringify(this.data, null, 2), 'utf8');
      } catch (e) {
        logger.error('保存封禁列表失败:', e.message);
      }
    });
    return this.savePromise;
  }

  check(ip) {
    if (!ip || this.isWhitelisted(ip)) return { blocked: false };
    
    const info = this.data.blocked_ips[ip];
    if (!info) return { blocked: false };

    if (info.permanent) {
      return { blocked: true, reason: 'permanent' };
    }
    
    if (info.expiresAt && Date.now() < info.expiresAt) {
      return { blocked: true, reason: 'temporary', expiresAt: info.expiresAt };
    }

    return { blocked: false };
  }

  async recordViolation(ip, type) {
    if (!ip || this.isWhitelisted(ip)) return;
    
    // 确保已初始化
    if (!this.initialized) await this.init();

    let info = this.data.blocked_ips[ip];
    const now = Date.now();

    if (!info) {
      info = { 
        permanent: false, 
        expiresAt: 0, 
        violations: 0, 
        tempBlockCount: 0, 
        lastViolation: 0 
      };
      this.data.blocked_ips[ip] = info;
    }

    // 如果已经在封禁中，不记录
    if (info.permanent || (info.expiresAt && now < info.expiresAt)) return;

    // 检查违规窗口：如果距离上次违规超过窗口期，重置计数
    if (now - info.lastViolation > VIOLATION_WINDOW) {
      info.violations = 0;
    }

    info.violations++;
    info.lastViolation = now;

    if (info.violations >= MAX_VIOLATIONS_BEFORE_TEMP_BLOCK) {
      // 触发封禁
      info.tempBlockCount++;
      info.violations = 0; // 重置违规计数

      if (info.tempBlockCount >= MAX_TEMP_BLOCKS_BEFORE_PERMANENT) {
        info.permanent = true;
        info.expiresAt = 0;
        logger.warn(`IP ${ip} 因频繁违规(${type})被永久封禁`);
      } else {
        info.expiresAt = now + TEMP_BLOCK_DURATION;
        logger.warn(`IP ${ip} 因频繁违规(${type})被临时封禁 1 小时 (累计封禁 ${info.tempBlockCount} 次)`);
      }
      
      await this.save();
    }
  }
}

export default new IpBlockManager();
