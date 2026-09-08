// server.js
// Backend simples: guarda o estado do app (casos, agências, tarefas) num
// arquivo JSON local, exige login (nome + senha compartilhada) pra acessar,
// registra quem acessou, e serve o front-end estático da pasta /public.
// Não usa nenhum pacote com compilação nativa -- só Node.js puro.

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const ATTACH_DIR = path.join(DATA_DIR, 'attachments');
const DATA_FILE = path.join(DATA_DIR, 'app-data.json');
const LOG_FILE = path.join(DATA_DIR, 'access-log.json');
const TI_AUTH_FILE = path.join(DATA_DIR, 'ti-auth.json');

// ======================================================================
// USUÁRIOS E SENHAS -- troque aqui quando quiser trocar as senhas do time.
// Todos usam a mesma senha padrão por enquanto; dá pra personalizar por
// usuário depois, só trocando o valor de cada chave.
// ======================================================================
const DEFAULT_PASSWORD = 'famtour123';
const ACCOUNTS = {
  'Suporte Comercial': process.env.APP_PASSWORD_SUPORTE || DEFAULT_PASSWORD,
};

// Gestão -- cada pessoa loga com o próprio nome (como o Executivo de Contas),
// todos começam com a mesma senha padrão; o TI troca por pessoa depois na
// tela "Trocar senha de qualquer conta".
const GESTAO_DEFAULT_PASSWORD = process.env.APP_PASSWORD_GESTAO || DEFAULT_PASSWORD;
const GESTAO_NAMES = ['Alison Monteiro', 'Paulo', 'Carol', 'Letícia', 'Mateus', 'Cristian', 'Alex', 'Marcelo'];
const GESTAO_PASSWORDS = Object.fromEntries(GESTAO_NAMES.map(n => [n, GESTAO_DEFAULT_PASSWORD]));

// Senha individual por executivo -- os 6 primeiros dígitos do CPF de cada um.
// Para trocar a senha de alguém, só editar o valor correspondente aqui.
const EXECUTIVO_PASSWORDS = {
  'Adriana Schlichta': '033286',
  'Afonso Domingues': '414359',
  'Alexandre Dias': '005639',
  'Alexandre Gomes': '158958',
  'Camila Fernandez': '721925',
  'Carla Meira': '465682',
  'Carlos Leonardi': '045184',
  'Daniela Reis': '096955',
  'Denilson Vicente': '307616',
  'Executivo Interno': 'Famtour123',
  'Fabio Viana': '331974',
  'Luiz Claudio': '855238',
  'Marcelo Souza': '272751',
  'Marcos Tre': '998651',
  'Nany Lima': '715460',
  'Pablo Santana': '025150',
  'Priscilla Bacalhao': '036446',
  'Rafael Andrade': '959694',
  'Roberto Lastoria': '808919',
  'Saulo Godoy': '295060',
  'Tiago Fantini': '281261',
};

const app = express();
app.set('trust proxy', true); // pega o IP real de quem acessa, não o do proxy do Railway
app.use(cors());
app.use(express.json({ limit: '25mb' }));

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ---- Sessões em memória (token -> {name, loginAt}) ----
// Reiniciar o servidor derruba todo mundo e pede login de novo -- aceitável
// pra esse porte de time.
const sessions = new Map();

function readJsonSafe(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  try { return JSON.parse(fs.readFileSync(file, 'utf-8')); }
  catch (e) { console.error(`ERRO lendo ${file}:`, e.message); return fallback; }
}

function writeJsonSafe(file, obj) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf-8');
  fs.renameSync(tmp, file);
}

// ======================================================================
// USUÁRIO TI (admin) -- acesso total + gerenciamento próprio de senha.
// A senha fica guardada com hash (nunca em texto puro), num arquivo que
// sobrevive a reinícios do servidor. Na primeira vez que o servidor sobe,
// cria a senha padrão abaixo -- depois disso, só muda através da tela de
// "Trocar senha" dentro do próprio app (perfil TI).
// ======================================================================
const TI_DEFAULT_PASSWORD = 'CTV3667ti#';

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function loadTiAuth() {
  let auth = readJsonSafe(TI_AUTH_FILE, null);
  if (!auth) {
    const salt = crypto.randomBytes(16).toString('hex');
    auth = { salt, hash: hashPassword(TI_DEFAULT_PASSWORD, salt), updatedAt: new Date().toISOString() };
    writeJsonSafe(TI_AUTH_FILE, auth);
  }
  return auth;
}

function verifyTiPassword(password) {
  const auth = loadTiAuth();
  return hashPassword(password, auth.salt) === auth.hash;
}

function setTiPassword(newPassword) {
  const salt = crypto.randomBytes(16).toString('hex');
  writeJsonSafe(TI_AUTH_FILE, { salt, hash: hashPassword(newPassword, salt), updatedAt: new Date().toISOString() });
}

loadTiAuth(); // garante que o arquivo de senha do TI já existe assim que o servidor sobe

// ======================================================================
// TROCA DE SENHA DE QUALQUER CONTA (só o TI pode fazer isso) -- guarda uma
// "sobreposição" de senha por conta/executivo, num arquivo separado. Se não
// houver sobreposição pra uma conta, o login continua usando a senha padrão
// definida em ACCOUNTS / EXECUTIVO_PASSWORDS normalmente.
// ======================================================================
const CREDENTIALS_FILE = path.join(DATA_DIR, 'credentials.json');

function loadCredentialOverrides() {
  return readJsonSafe(CREDENTIALS_FILE, {});
}

function getCredentialOverride(key) {
  const store = loadCredentialOverrides();
  return store[key] || null;
}

function verifyAccountPassword(key, password, defaultPassword) {
  const override = getCredentialOverride(key);
  if (override) return hashPassword(password, override.salt) === override.hash;
  return password === defaultPassword;
}

function setAccountPassword(key, newPassword) {
  const store = loadCredentialOverrides();
  const salt = crypto.randomBytes(16).toString('hex');
  store[key] = { salt, hash: hashPassword(newPassword, salt), updatedAt: new Date().toISOString() };
  writeJsonSafe(CREDENTIALS_FILE, store);
}

function isPrivateIp(ip) {
  if (!ip) return true;
  const clean = ip.replace('::ffff:', '');
  return clean === '127.0.0.1' || clean === '::1' || clean.startsWith('10.') ||
    clean.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(clean);
}

async function lookupLocation(ip) {
  if (isPrivateIp(ip)) return 'Rede local';
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,city,regionName,country`);
    const data = await res.json();
    if (data.status === 'success') {
      return [data.city, data.regionName, data.country].filter(Boolean).join(', ') || 'Desconhecido';
    }
  } catch (e) { /* serviço de geolocalização indisponível no momento -- segue sem travar o login */ }
  return 'Desconhecido';
}

function appendAccessLog(entry) {
  const log = readJsonSafe(LOG_FILE, []);
  log.push(entry);
  while (log.length > 500) log.shift();
  writeJsonSafe(LOG_FILE, log);
}

// ---- Autenticação ----

app.post('/api/login', async (req, res) => {
  const { account, password, name } = req.body || {};
  const location = await lookupLocation(req.ip);

  if (account === 'TI') {
    if (!verifyTiPassword(password)) {
      appendAccessLog({ account, ip: req.ip, location, when: new Date().toISOString(), result: 'senha incorreta' });
      return res.status(401).json({ error: 'Senha incorreta.' });
    }
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, { account, loginAt: new Date().toISOString() });
    appendAccessLog({ account, ip: req.ip, location, when: new Date().toISOString(), result: 'login ok' });
    return res.json({ ok: true, token, account });
  }

  if (account === 'Executivo de Contas') {
    if (!name || !Object.prototype.hasOwnProperty.call(EXECUTIVO_PASSWORDS, name)) {
      return res.status(400).json({ error: 'Selecione o executivo.' });
    }
    if (!verifyAccountPassword(`exec:${name}`, password, EXECUTIVO_PASSWORDS[name])) {
      appendAccessLog({ account, name, ip: req.ip, location, when: new Date().toISOString(), result: 'senha incorreta' });
      return res.status(401).json({ error: 'Senha incorreta.' });
    }
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, { account, name, loginAt: new Date().toISOString() });
    appendAccessLog({ account, name, ip: req.ip, location, when: new Date().toISOString(), result: 'login ok' });
    return res.json({ ok: true, token, account, name });
  }

  if (account === 'Gestão') {
    if (!name || !Object.prototype.hasOwnProperty.call(GESTAO_PASSWORDS, name)) {
      return res.status(400).json({ error: 'Selecione seu nome.' });
    }
    if (!verifyAccountPassword(`gestao:${name}`, password, GESTAO_PASSWORDS[name])) {
      appendAccessLog({ account, name, ip: req.ip, location, when: new Date().toISOString(), result: 'senha incorreta' });
      return res.status(401).json({ error: 'Senha incorreta.' });
    }
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, { account, name, loginAt: new Date().toISOString() });
    appendAccessLog({ account, name, ip: req.ip, location, when: new Date().toISOString(), result: 'login ok' });
    return res.json({ ok: true, token, account, name });
  }

  if (!account || !Object.prototype.hasOwnProperty.call(ACCOUNTS, account)) {
    return res.status(400).json({ error: 'Selecione um usuário válido.' });
  }
  if (!verifyAccountPassword(account, password, ACCOUNTS[account])) {
    appendAccessLog({ account, ip: req.ip, location, when: new Date().toISOString(), result: 'senha incorreta' });
    return res.status(401).json({ error: 'Senha incorreta.' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { account, loginAt: new Date().toISOString() });
  appendAccessLog({ account, ip: req.ip, location, when: new Date().toISOString(), result: 'login ok' });
  res.json({ ok: true, token, account });
});

app.post('/api/logout', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  sessions.delete(token);
  res.json({ ok: true });
});

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const session = sessions.get(token);
  if (!session) {
    return res.status(401).json({ error: 'Sessão inválida ou expirada. Faça login novamente.' });
  }
  req.user = session;
  next();
}

app.get('/api/access-log', requireAuth, (req, res) => {
  if (req.user.account !== 'TI') {
    return res.status(403).json({ error: 'Sem permissão para ver o log de acessos.' });
  }
  const log = readJsonSafe(LOG_FILE, []);
  res.json(log.slice(-100).reverse());
});

// Troca de senha -- exclusiva do perfil TI, exige a senha atual pra confirmar
app.post('/api/admin/change-password', requireAuth, (req, res) => {
  if (req.user.account !== 'TI') {
    return res.status(403).json({ error: 'Só o usuário TI pode trocar a própria senha.' });
  }
  const { currentPassword, newPassword } = req.body || {};
  if (!verifyTiPassword(currentPassword || '')) {
    return res.status(401).json({ error: 'Senha atual incorreta.' });
  }
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'A nova senha precisa ter pelo menos 8 caracteres.' });
  }
  setTiPassword(newPassword);
  appendAccessLog({ account: 'TI', ip: req.ip, when: new Date().toISOString(), result: 'senha alterada' });
  res.json({ ok: true });
});

// Troca a senha de QUALQUER conta (Suporte Comercial, Gestão ou um executivo
// específico) -- exclusivo do TI, não exige a senha atual da conta alvo.
app.post('/api/admin/set-account-password', requireAuth, (req, res) => {
  if (req.user.account !== 'TI') {
    return res.status(403).json({ error: 'Só o usuário TI pode trocar a senha de outras contas.' });
  }
  const { targetType, targetKey, newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'A nova senha precisa ter pelo menos 6 caracteres.' });
  }
  let credentialKey;
  let label;
  if (targetType === 'executivo') {
    if (!targetKey || !Object.prototype.hasOwnProperty.call(EXECUTIVO_PASSWORDS, targetKey)) {
      return res.status(400).json({ error: 'Executivo inválido.' });
    }
    credentialKey = `exec:${targetKey}`;
    label = targetKey;
  } else if (targetType === 'gestao') {
    if (!targetKey || !Object.prototype.hasOwnProperty.call(GESTAO_PASSWORDS, targetKey)) {
      return res.status(400).json({ error: 'Pessoa de Gestão inválida.' });
    }
    credentialKey = `gestao:${targetKey}`;
    label = targetKey;
  } else {
    if (!targetKey || !Object.prototype.hasOwnProperty.call(ACCOUNTS, targetKey)) {
      return res.status(400).json({ error: 'Conta inválida.' });
    }
    credentialKey = targetKey;
    label = targetKey;
  }
  setAccountPassword(credentialKey, newPassword);
  appendAccessLog({ account: 'TI', ip: req.ip, when: new Date().toISOString(), result: `senha de "${label}" alterada pelo TI` });
  res.json({ ok: true });
});

// ======================================================================
// ANEXOS (imagens de marketing e PDFs de day-by-day) -- ficam guardados
// como arquivos separados em disco, NÃO dentro do app-data.json. O JSON
// principal só guarda uma referência (URL curta) pra cada arquivo. Isso
// evita que o arquivo de dados fique gigante conforme mais FAMTOURs (com
// foto e PDF) forem cadastrados.
// ======================================================================

function safeExt(filename) {
  const m = /\.([a-zA-Z0-9]+)$/.exec(filename || '');
  return m ? m[1].toLowerCase().replace(/[^a-z0-9]/g, '') || 'bin' : 'bin';
}

app.post('/api/upload', requireAuth, (req, res) => {
  const { dataUrl, filename } = req.body || {};
  if (!dataUrl || typeof dataUrl !== 'string' || !dataUrl.startsWith('data:')) {
    return res.status(400).json({ error: 'Arquivo inválido.' });
  }
  const match = /^data:([^;]+);base64,(.+)$/.exec(dataUrl);
  if (!match) return res.status(400).json({ error: 'Formato de arquivo inválido.' });
  const buffer = Buffer.from(match[2], 'base64');
  if (buffer.length > 20 * 1024 * 1024) {
    return res.status(413).json({ error: 'Arquivo maior que 20MB.' });
  }
  if (!fs.existsSync(ATTACH_DIR)) fs.mkdirSync(ATTACH_DIR, { recursive: true });
  const storedName = `${crypto.randomBytes(12).toString('hex')}.${safeExt(filename)}`;
  fs.writeFileSync(path.join(ATTACH_DIR, storedName), buffer);
  res.json({ ok: true, url: `/api/attachments/${storedName}`, filename: filename || storedName });
});

// Servido sem exigir login -- o nome do arquivo é um código aleatório
// impossível de adivinhar, funcionando como as URLs "opacas" de qualquer
// serviço de armazenamento de arquivos (S3, Google Drive, etc.). Isso é
// necessário porque tags <img> não conseguem mandar o token de login.
app.get('/api/attachments/:filename', (req, res) => {
  const filename = req.params.filename;
  if (!/^[a-f0-9]{24}\.[a-z0-9]+$/.test(filename)) {
    return res.status(400).send('Nome de arquivo inválido.');
  }
  const full = path.join(ATTACH_DIR, filename);
  if (!fs.existsSync(full)) return res.status(404).send('Arquivo não encontrado.');
  res.sendFile(full);
});

// Migração única: converte anexos antigos (guardados em base64 dentro do
// próprio FAMTOUR) para o novo formato de arquivo separado. Só o TI pode
// rodar isso, e é seguro rodar mais de uma vez (já migrados são ignorados).
app.post('/api/admin/migrate-attachments', requireAuth, requireTi, (req, res) => {
  try {
    const state = readState();
    let migrated = 0;
    if (!fs.existsSync(ATTACH_DIR)) fs.mkdirSync(ATTACH_DIR, { recursive: true });

    function migrateOne(obj, dataUrlField, urlField, filenameField, fallbackName) {
      if (!obj || !obj[dataUrlField]) return;
      const match = /^data:([^;]+);base64,(.+)$/.exec(obj[dataUrlField]);
      if (!match) return;
      const buffer = Buffer.from(match[2], 'base64');
      const name = obj[filenameField] || fallbackName;
      const storedName = `${crypto.randomBytes(12).toString('hex')}.${safeExt(name)}`;
      fs.writeFileSync(path.join(ATTACH_DIR, storedName), buffer);
      obj[urlField] = `/api/attachments/${storedName}`;
      delete obj[dataUrlField];
      migrated++;
    }

    (state.data.cases || []).forEach(c => {
      if (c.marketing && Array.isArray(c.marketing.imagens)) {
        c.marketing.imagens.forEach(img => migrateOne(img, 'dataUrl', 'url', 'name', 'imagem.jpg'));
      }
      migrateOne(c.dayByDay, 'dataUrl', 'url', 'filename', 'daybyday.pdf');
    });

    if (migrated > 0) {
      state.updated_at = new Date().toISOString();
      state.updated_by = 'TI (migração de anexos)';
      writeJsonSafe(DATA_FILE, state);
    }
    res.json({ ok: true, migrated });
  } catch (e) {
    console.error('Erro na migração de anexos:', e.message);
    res.status(500).json({ error: 'Falha na migração: ' + e.message });
  }
});

// ---- Estado do app (protegido por login) ----

function readState() {
  if (!fs.existsSync(DATA_FILE)) {
    const initial = {
      data: { cases: [], activeId: null },
      updated_at: new Date().toISOString(),
      updated_by: 'sistema'
    };
    writeJsonSafe(DATA_FILE, initial);
    return initial;
  }
  return readJsonSafe(DATA_FILE, { data: { cases: [], activeId: null }, updated_at: null, updated_by: null });
}

let writeQueue = Promise.resolve();
function queueWrite(state) {
  writeQueue = writeQueue.then(() => writeJsonSafe(DATA_FILE, state));
  return writeQueue;
}

// Endpoint leve pra checar se algo mudou, sem baixar o estado inteiro
// (evita re-baixar imagens/PDFs em base64 a cada verificação de 8s)
app.get('/api/state/meta', requireAuth, (req, res) => {
  try {
    const state = readState();
    res.json({ updated_at: state.updated_at, updated_by: state.updated_by });
  } catch (e) {
    res.status(500).json({ error: 'Não foi possível checar atualizações.' });
  }
});

app.get('/api/state', requireAuth, (req, res) => {
  try {
    res.json(readState());
  } catch (e) {
    res.status(500).json({ error: 'Não foi possível ler os dados salvos.' });
  }
});

app.put('/api/state', requireAuth, async (req, res) => {
  const { data } = req.body;
  if (!data || typeof data !== 'object') {
    return res.status(400).json({ error: 'Campo "data" é obrigatório e deve ser um objeto.' });
  }
  const state = {
    data,
    updated_at: new Date().toISOString(),
    updated_by: req.user.account
  };
  try {
    await queueWrite(state);
    res.json({ ok: true, updated_at: state.updated_at });
  } catch (e) {
    res.status(500).json({ error: 'Não foi possível salvar os dados.' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// ======================================================================
// BACKUP -- guarda uma cópia diária do arquivo de dados (últimos 14 dias),
// separada do arquivo principal, pra proteger contra corrupção ou perda
// acidental. Além disso, o TI pode baixar uma cópia manual a qualquer hora.
// ======================================================================
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const BACKUP_RETENTION_DAYS = 14;

function runDailyBackup() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const dest = path.join(BACKUP_DIR, `backup-${today}.json`);
    fs.copyFileSync(DATA_FILE, dest);

    // limpa backups mais antigos que a janela de retenção
    const cutoff = Date.now() - BACKUP_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    fs.readdirSync(BACKUP_DIR).forEach(f => {
      const full = path.join(BACKUP_DIR, f);
      const stat = fs.statSync(full);
      if (stat.mtimeMs < cutoff) fs.unlinkSync(full);
    });
    console.log(`Backup diário salvo: ${dest}`);
  } catch (e) {
    console.error('Falha ao gerar backup diário:', e.message);
  }
}

runDailyBackup(); // já garante uma cópia assim que o servidor sobe
setInterval(runDailyBackup, 24 * 60 * 60 * 1000); // repete a cada 24h

function requireTi(req, res, next) {
  if (req.user.account !== 'TI') {
    return res.status(403).json({ error: 'Só o usuário TI pode acessar isso.' });
  }
  next();
}

// Baixa uma cópia dos dados atuais, na hora
app.get('/api/admin/backup', requireAuth, requireTi, (req, res) => {
  if (!fs.existsSync(DATA_FILE)) {
    return res.status(404).json({ error: 'Nenhum dado salvo ainda.' });
  }
  const today = new Date().toISOString().slice(0, 10);
  res.setHeader('Content-Disposition', `attachment; filename="famtour-backup-${today}.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.sendFile(DATA_FILE);
});

// Lista os backups automáticos guardados
app.get('/api/admin/backups', requireAuth, requireTi, (req, res) => {
  if (!fs.existsSync(BACKUP_DIR)) return res.json([]);
  const list = fs.readdirSync(BACKUP_DIR)
    .filter(f => f.endsWith('.json'))
    .map(f => {
      const stat = fs.statSync(path.join(BACKUP_DIR, f));
      return { filename: f, sizeKb: Math.round(stat.size / 1024), when: stat.mtime.toISOString() };
    })
    .sort((a, b) => b.when.localeCompare(a.when));
  res.json(list);
});

// Baixa um backup específico da lista
app.get('/api/admin/backups/:filename', requireAuth, requireTi, (req, res) => {
  const filename = req.params.filename;
  if (!/^backup-\d{4}-\d{2}-\d{2}\.json$/.test(filename)) {
    return res.status(400).json({ error: 'Nome de arquivo inválido.' });
  }
  const full = path.join(BACKUP_DIR, filename);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'Backup não encontrado.' });
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'application/json');
  res.sendFile(full);
});

// ---- Front-end estático ----
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando em http://0.0.0.0:${PORT}`);
  console.log(`Dados salvos em: ${DATA_FILE}`);
  console.log(`Usuários e senha padrão (${DEFAULT_PASSWORD}):`, Object.keys(ACCOUNTS).join(', '));
});
