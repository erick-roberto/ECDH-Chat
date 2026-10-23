import { useEffect, useMemo, useRef, useState } from 'react';
import {
  createIdentity,
  publicFromPrivate,
  validatePrivateKey,
  signRegistration,
  newGroupID,
  signGroupGrant,
  verifyGroupGrant,
  fingerprint,
} from './crypto';
import { runCrypto } from './workerClient';
import { saveIdentitySecurely, loadIdentitySecurely, hasSecureIdentity } from './vault';
import { createSocket, emitAck } from './socket';
import { pinKey, acceptNewKey, alreadySeen } from './keyring';

const LOCAL_MESSAGES_PREFIX = 'chat-ecc.messages.v1:';

function readLocalMessages(userID) {
  if (!userID) return [];

  try {
    const saved = localStorage.getItem(`${LOCAL_MESSAGES_PREFIX}${userID}`);
    const messages = saved ? JSON.parse(saved) : [];

    return Array.isArray(messages) ? messages : [];
  } catch {
    return [];
  }
}

function formatTime(timestamp) {
  if (!timestamp) return '';
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return '';
  const today = new Date();
  const isToday = date.toDateString() === today.toDateString();
  if (isToday) {
    return date.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  }
  return date.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
}

function getLastMessage(messages, userID) {
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].peer === userID) return messages[i];
  }
  return null;
}

export default function App() {
  const socket = useMemo(() => createSocket(), []);

  const [isLocked, setIsLocked] = useState(hasSecureIdentity());
  const [vaultPassword, setVaultPassword] = useState('');
  
  const [identity, setIdentity] = useState(null);
  const [userID, setUserID] = useState('');
  const [status, setStatus] = useState('Desconectado');
  const [users, setUsers] = useState([]);
  const [target, setTarget] = useState('');
  const [draft, setDraft] = useState('');
  const [messages, setMessages] = useState([]);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [privateImport, setPrivateImport] = useState('');
  const [groupMembers, setGroupMembers] = useState('');
  const [groupID, setGroupID] = useState('');
  const [conversationSearch, setConversationSearch] = useState('');
  const [groups, setGroups] = useState([]);
  const [activeGroupID, setActiveGroupID] = useState('');

  const identityRef = useRef(identity);
  const userRef = useRef(userID);

  function rememberMessage(message) {
    const currentUserID = identityRef.current?.userID;

    if (currentUserID) {
      try {
        const saved = readLocalMessages(currentUserID);
        const key = item =>
          `${item.type || 'direct'}:${item.groupID || ''}:${item.id}`;

        const updated = [
          ...saved.filter(item => key(item) !== key(message)),
          message,
        ];

        localStorage.setItem(
          `${LOCAL_MESSAGES_PREFIX}${currentUserID}`,
          JSON.stringify(updated)
        );
      } catch (error) {
        console.error('Não foi possível salvar o histórico local:', error);
      }
    }

    setMessages(previous => {
      const key = item =>
        `${item.type || 'direct'}:${item.groupID || ''}:${item.id}`;

      if (previous.some(item => key(item) === key(message))) {
        return previous.map(item =>
          key(item) === key(message) ? { ...item, ...message } : item
        );
      }

      return [...previous, message];
    });
  }

  const targetRef = useRef(target);
  const messageListRef = useRef(null);

  useEffect(() => { identityRef.current = identity; }, [identity]);
  useEffect(() => { userRef.current = userID; }, [userID]);
  useEffect(() => { targetRef.current = target; }, [target]);

  const conversations = useMemo(() => {
    const directMessages = messages.filter(message => !message.groupID && message.type !== 'group');
    const contactIDs = new Set(users);
    directMessages.forEach(message => { if (message.peer) contactIDs.add(message.peer); });
    contactIDs.delete(identity?.userID || userID);

    return Array.from(contactIDs)
      .map(id => {
        const lastMessage = getLastMessage(directMessages, id);
        return {
          id,
          lastMessage,
          lastTimestamp: lastMessage?.timestamp || 0,
          online: users.includes(id),
        };
      })
      .sort((a, b) => {
        if (a.lastTimestamp !== b.lastTimestamp) return b.lastTimestamp - a.lastTimestamp;
        if (a.online !== b.online) return Number(b.online) - Number(a.online);
        return a.id.localeCompare(b.id);
      });
  }, [users, messages, identity, userID]);

  const filteredConversations = useMemo(() => {
    const query = conversationSearch.trim().toLocaleLowerCase('pt-BR');
    if (!query) return conversations;
    return conversations.filter(conv => conv.id.toLocaleLowerCase('pt-BR').includes(query));
  }, [conversations, conversationSearch]);

  const activeMessages = useMemo(() => {
    const filteredMessages = activeGroupID
      ? messages.filter(message => message.groupID === activeGroupID)
      : messages.filter(
          message => !message.groupID && message.peer === target
        );

    return [...filteredMessages].sort((a, b) => {
      const timeA = Number(a.timestamp) || 0;
      const timeB = Number(b.timestamp) || 0;

      return timeA - timeB;
    });
  }, [messages, target, activeGroupID]);

  useEffect(() => {
    const element = messageListRef.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [activeMessages, target]);

  useEffect(() => {
    socket.on('connect', () => setStatus('Conectado'));
    socket.on('disconnect', () => setStatus('Desconectado'));
    socket.on('connect_error', err => setNotice(`Falha de conexão: ${err.message}`));
    socket.on('user_list_update', list => {
      setUsers(Array.isArray(list) ? list.filter(id => id !== userRef.current) : []);
    });
    socket.on('receive_encrypted_message', packet => handleIncoming(packet));
    socket.on('receive_group_encrypted_message', packet => handleIncomingGroup(packet));
    socket.on('your_groups', async groupList => {
      const accepted = [];
      for (const group of Array.isArray(groupList) ? groupList : []) {
        if (acceptGroup(group)) accepted.push(group);
      }
      setGroups(accepted);
    });
    socket.on('group_created', groupData => {
      if (!acceptGroup(groupData)) return;
      setGroups(prev => [...prev.filter(g => g.groupID !== groupData.groupID), groupData]);
    });
    socket.on('pending_messages', async (packets, ack) => {
      try {
        await Promise.all(
          (packets || []).map(packet =>
            packet.type === 'group'
              ? handleIncomingGroup(packet, true)
              : handleIncoming(packet, true)
          )
        );

        if (typeof ack === 'function') {
          ack({ success: true });
        }
      } catch (error) {
        console.error('Erro ao processar mensagens pendentes:', error);

        if (typeof ack === 'function') {
          ack({ success: false });
        }
      }
    });

    return () => {
      socket.removeAllListeners();
      socket.disconnect();
    };
  }, []);

  async function unlockVault(event) {
    event.preventDefault();
    setBusy(true);
    try {
      const id = await loadIdentitySecurely(vaultPassword);
      setIdentity(id);
      setUserID(id.userID);
      setMessages(readLocalMessages(id.userID));
      setIsLocked(false);
      setNotice('Cofre desbloqueado. Identidade carregada.');
    } catch (error) {
      setNotice(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function register(id, ident, password) {
    const normalizedID = id.trim();
    if (!normalizedID) throw new Error('Informe um identificador de usuário.');

    const challenge = await emitAck(socket, 'get_auth_challenge', {});
    if (!challenge.success || !challenge.nonce) throw new Error('Não foi possível obter o desafio de autenticação.');

    const response = await emitAck(socket, 'register_public_key', {
      userID: normalizedID,
      publicKey: ident.publicKey,
      signature: signRegistration(ident.privateKey, normalizedID, challenge.nonce),
    });

    if (!response.success) throw new Error(response.message || 'Registro recusado.');

    const next = { ...ident, userID: normalizedID };
    
    await saveIdentitySecurely(next, password);
    
    setIdentity(next);
    identityRef.current = next;
    setUserID(normalizedID);
    userRef.current = normalizedID;
    setMessages(readLocalMessages(normalizedID));
    setIsLocked(false);

    setNotice('Identidade registrada e guardada em segurança no cofre local.');
  }

  async function ensureConnected() {
    if (socket.connected) return;
    await new Promise((resolve, reject) => {
      const onConnect = () => { cleanup(); resolve(); };
      const onError = err => { cleanup(); reject(err); };
      const cleanup = () => { socket.off('connect', onConnect); socket.off('connect_error', onError); };
      socket.once('connect', onConnect);
      socket.once('connect_error', onError);
      socket.connect();
    });
  }

  async function createNewIdentity() {
    setBusy(true);
    try {
      const id = userID.trim();
      if (!id) throw new Error('Informe o identificador antes de gerar a identidade.');
      if (!vaultPassword || vaultPassword.length < 3) throw new Error('Crie uma palavra-passe (min. 3 caracteres) para o cofre.');

      await ensureConnected();
      const ident = createIdentity();
      await register(id, ident, vaultPassword);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function reconnect() {
    setBusy(true);
    try {
      if (!identity) throw new Error('Desbloqueie o cofre primeiro.');
      await ensureConnected();
      await register(userID || identity.userID, identity, vaultPassword);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function importIdentity() {
    setBusy(true);
    try {
      if (!vaultPassword || vaultPassword.length < 4) throw new Error('Crie uma palavra-passe forte para o cofre.');
      
      const privateKey = privateImport.trim().toLowerCase();
      validatePrivateKey(privateKey);
      
      const imported = { privateKey, publicKey: publicFromPrivate(privateKey) };
      await ensureConnected();
      await register(userID, imported, vaultPassword);
      setPrivateImport('');
    } catch (error) {
      setNotice(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function getPeerKey(peerID) {
    const res = await emitAck(socket, 'request_public_key', { targetUserID: peerID });
    if (!res.success) throw new Error(res.message || 'Não foi possível obter a chave pública do usuário.');

    const pin = pinKey(peerID, res.publicKey);
    
    if (pin.status === 'new') {
      setNotice(`Primeiro contato com "${peerID}". Confirme que o fingerprint é: ${fingerprint(res.publicKey)}`);
    } else if (pin.status === 'changed') {
      const accept = window.confirm(
        `ATENÇÃO: A chave pública de "${peerID}" mudou!\n\n` +
        `Pode ser um ataque (MITM) ou o utilizador reinstalou a aplicação e gerou uma nova chave.\n\n` +
        `Novo Fingerprint: ${fingerprint(res.publicKey)}\n\n` +
        `Aceitar nova chave?`
      );
      
      if (accept) {
        acceptNewKey(peerID, res.publicKey);
      } else {
        throw new Error(`A chave pública de ${peerID} mudou e a alteração foi rejeitada.`);
      }
    }
    return res.publicKey;
  }

  function acceptGroup(group) {
    try {
      const keys = group?.groupKeys;
      if (!group || !Array.isArray(keys) || !Array.isArray(group.members)) return false;
      const names = keys.map(item => item.username).sort().join('|');
      if (names !== [...group.members].sort().join('|')) return false;

      for (const item of keys) {
        const pin = pinKey(item.username, item.publicKey);
        if(pin.status === 'changed') acceptNewKey(item.username, item.publicKey); 
      }

      const creatorKey = keys.find(item => item.username === group.createdBy)?.publicKey;
      if (!creatorKey || !verifyGroupGrant(group, creatorKey)) {
        setNotice('Grupo recusado: assinatura do criador inválida.');
        return false;
      }
      return true;
    } catch (error) {
      setNotice(`Grupo recusado: ${error.message}`);
      return false;
    }
  }

  async function handleIncoming(packet, queued = false, fromHistory = false) {
    try {
      const me = identityRef.current;

      if (!me || packet.receiverID !== me.userID) {
        if (queued) {
          throw new Error(
            'Destinatário da mensagem direta inválido ou identidade indisponível.'
          );
        }

        return;
      }

      const senderKey = await getPeerKey(packet.senderID);

      const { plaintext, messageId, sentAt } = await runCrypto(
        'decryptAndVerify', packet, me.privateKey, senderKey, me.userID
      );

      // No histórico, a deduplicação é feita pelo identificador da mensagem.
      if (!fromHistory && alreadySeen(messageId)) return;

      rememberMessage({
        id: messageId,
        direction: 'in',
        peer: packet.senderID,
        text: plaintext,
        timestamp: sentAt,
        queued,
      });
    } catch (error) {
      setNotice(`Mensagem recebida rejeitada: ${error.message}`);
      if (queued) throw error;
    }
  }

  async function loadConversationHistory(peerID) {
    const me = identityRef.current;

    if (!me || !peerID || !socket.connected) return;

    try {
      const response = await emitAck(socket, 'request_direct_history', { peerID });

      if (!response.success) {
        throw new Error(response.message || 'Falha ao carregar o histórico.');
      }

      const history = Array.isArray(response.messages) ? response.messages : [];

      for (const packet of history) {
        // Mensagens recebidas podem ser descriptografadas neste dispositivo.
        if (packet.receiverID === me.userID) {
          await handleIncoming(packet, false, true);
        }

        // Mensagens enviadas são restauradas do armazenamento local.
        // O servidor possui somente o pacote cifrado para o destinatário.
      }
    } catch (error) {
      setNotice(`Erro ao carregar histórico: ${error.message}`);
    }
  }

  async function handleIncomingGroup(packet, isPending = false) {
    try {
      const me = identityRef.current;

      if (!me || packet.receiverID !== me.userID) {
        if (isPending) {
          throw new Error(
            'Destinatário da mensagem de grupo inválido ou identidade indisponível.'
          );
        }

        return;
      }

      const senderKey = await getPeerKey(packet.senderID);

      const { plaintext, messageId, sentAt } = await runCrypto(
        'decryptGroupAndVerify', packet, me.privateKey, senderKey, me.userID
      );

      if (alreadySeen(`${packet.groupID}:${messageId}`)) return;

      rememberMessage({
        id: messageId,
        type: 'group',
        groupID: packet.groupID,
        peer: packet.senderID,
        direction: 'in',
        text: plaintext,
        timestamp: sentAt,
      });
    } catch (error) {
      setNotice(`Mensagem de grupo rejeitada: ${error.message}`);
      throw error;
    }
  }

  async function sendMessage(event) {
    event.preventDefault();
    if (activeGroupID) {
      setBusy(true);
      try { await sendGroupMessage(); } 
      catch (error) { setNotice(error.message); } 
      finally { setBusy(false); }
      return;
    }

    setBusy(true);
    try {
      const me = identityRef.current;
      const recipient = targetRef.current;

      if (!me) throw new Error('Desbloqueie ou registe uma identidade primeiro.');
      if (!recipient || recipient === me.userID) throw new Error('Escolha outro usuário.');
      if (!draft.trim()) throw new Error('Digite uma mensagem.');
      if (new TextEncoder().encode(draft).length > 28) throw new Error('A mensagem ultrapassa o limite de 28 bytes UTF-8.');

      const recipientKey = await getPeerKey(recipient);

      const packet = await runCrypto(
        'encryptForRecipient', draft, recipientKey, me.privateKey, me.userID, recipient
      );

      const response = await emitAck(socket, 'send_encrypted_message', packet);
      if (!response.success) throw new Error(response.message || 'Envio recusado.');

      rememberMessage({
        id: packet.messageId,
        direction: 'out',
        peer: recipient,
        text: draft,
        timestamp: packet.sentAt,
      });

      setDraft('');
      setNotice(response.delivered ? 'Mensagem cifrada encaminhada.' : 'Mensagem armazenada na fila offline.');
    } catch (error) {
      setNotice(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function sendGroupMessage() {
    const me = identityRef.current;
    const group = groups.find(item => item.groupID === activeGroupID);

    if (!me) throw new Error('Registre uma identidade primeiro.');
    if (!group) throw new Error('Grupo não encontrado nesta sessão.');
    if (!draft.trim()) throw new Error('Digite uma mensagem.');
    if (new TextEncoder().encode(draft).length > 28) throw new Error('A mensagem ultrapassa o limite de 28 bytes UTF-8.');

    for (const item of group.groupKeys) {
      const pin = pinKey(item.username, item.publicKey);
      if(pin.status === 'changed') acceptNewKey(item.username, item.publicKey); 
    }

    const encryptedPacket = await runCrypto(
      'encryptForGroup', draft, group.groupID, group.groupKeys, me.privateKey, me.userID
    );

    const response = await emitAck(socket, 'send_group_encrypted_message', encryptedPacket);
    if (!response.success) throw new Error(response.message || 'Envio da mensagem de grupo recusado.');

    rememberMessage({
      id: encryptedPacket.messageId,
      type: 'group',
      groupID: group.groupID,
      peer: me.userID,
      direction: 'out',
      text: draft,
      timestamp: encryptedPacket.sentAt,
    });

    setDraft('');
    setNotice(`Mensagem de grupo encaminhada. Entregues: ${response.delivered || 0}; fila: ${response.queued || 0}; falhas: ${response.failed || 0}.`);
  }

  async function createGroup(event) {
    event.preventDefault();
    setBusy(true);
    try {
      const members = groupMembers.split(',').map(value => value.trim()).filter(Boolean);
      const me = identityRef.current;
      if (!me) throw new Error('Desbloqueie ou registe uma identidade primeiro.');

      const allMembers = [...new Set([me.userID, ...members])];
      const newID = newGroupID();

      const response = await emitAck(socket, 'create_group', {
        groupID: newID,
        members: allMembers,
        signature: signGroupGrant(me.privateKey, newID, allMembers, me.userID),
      });

      if (!response.success) throw new Error(response.message || 'Não foi possível criar o grupo.');

      const newGroup = {
        groupID: response.groupID, members: response.members, groupKeys: response.groupKeys,
        createdBy: response.createdBy || me.userID, signature: response.signature,
      };

      if (!acceptGroup(newGroup)) throw new Error('O servidor devolveu um grupo inconsistente.');

      setGroups(prev => [...prev.filter(g => g.groupID !== newGroup.groupID), newGroup]);
      setTarget('');
      targetRef.current = '';
      setActiveGroupID(newGroup.groupID);
      setGroupID(newGroup.groupID);
      setGroupMembers('');
      setNotice(`Grupo criado com ${newGroup.members.length} participantes.`);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setBusy(false);
    }
  }

  function openConversation(id) {
    setActiveGroupID('');
    setTarget(id);
    targetRef.current = id;

    loadConversationHistory(id);
  }
  function openGroup(grpID) {
    setTarget(''); targetRef.current = ''; setActiveGroupID(grpID);
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand-mark">E</div>
        <div>
          <h1>ECDH-Chat</h1>
          <p>Mensagens com criptografia de curva elíptica</p>
        </div>
        <span className={`connection ${status === 'Conectado' ? 'online' : ''}`}>{status}</span>
      </header>

      {notice && (
        <div className="notice" role="status">
          <span>{notice}</span>
          <button className="icon-button" onClick={() => setNotice('')} aria-label="Fechar aviso">×</button>
        </div>
      )}

      <section className="panel identity-panel">
        <div className="section-heading">
          <div>
            <span className="eyebrow">ETAPA 01</span>
            <h2>Sua identidade</h2>
          </div>
          <span className="pill">AES-GCM Local · secp256k1</span>
        </div>

        {isLocked ? (
          <form onSubmit={unlockVault} className="identity-grid">
            <label>
              Cofre local encontrado. Introduza a palavra-passe:
              <input type="password" value={vaultPassword} onChange={e => setVaultPassword(e.target.value)} placeholder="Palavra-passe do cofre" />
            </label>
            <div className="button-row">
              <button disabled={busy || vaultPassword.length === 0} type="submit">Desbloquear Cofre</button>
            </div>
          </form>
        ) : !identity ? (
          <>
            <div className="identity-grid" style={{marginBottom: "15px"}}>
              <label>Identificador de usuário<input value={userID} onChange={e => setUserID(e.target.value)} placeholder="ex.: alice" maxLength={128} /></label>
              <label>Criar palavra-passe para o Cofre (Local)<input type="password" value={vaultPassword} onChange={e => setVaultPassword(e.target.value)} placeholder="Mínimo 3 caracteres" /></label>
            </div>
            <div className="button-row">
              <button onClick={createNewIdentity} disabled={busy || !userID.trim() || vaultPassword.length < 3}>Gerar identidade encriptada</button>
            </div>
            
            <details className="import-details">
              <summary>Importar chave privada existente</summary>
              <label>Chave privada hexadecimal (32 bytes)<input value={privateImport} onChange={e => setPrivateImport(e.target.value)} placeholder="64 caracteres hexadecimais" autoComplete="off" /></label>
              <button className="secondary" onClick={importIdentity} disabled={busy || !privateImport.trim() || vaultPassword.length < 3}>Importar para o cofre</button>
            </details>
          </>
        ) : (
          <div className="key-card">
            <div><span className="key-label">Identidade local</span><strong>{identity.userID || userID}</strong></div>
            <div><span className="key-label">Chave pública</span><code>{identity.publicKey}</code></div>
            <div><span className="key-label">Fingerprint (confira com seus contatos)</span><code>{fingerprint(identity.publicKey)}</code></div>
            <p>
              A sua chave privada está armazenada em segurança, encriptada com a sua palavra-passe usando AES-GCM (Proteção XSS).
            </p>
            <button className="secondary" onClick={reconnect} disabled={busy}>Reconectar Sessão</button>
          </div>
        )}
      </section>

      <div className="content-grid">
        <aside className="side-column">
          <section className="panel conversations-panel">
            <div className="section-heading">
              <div><span className="eyebrow">MENSAGENS</span><h2>Conversas</h2></div>
              <span className="count">{conversations.length}</span>
            </div>

            <div className="conversation-search">
              <span aria-hidden="true">⌕</span>
              <input type="search" value={conversationSearch} onChange={e => setConversationSearch(e.target.value)} placeholder="Buscar conversas..." />
            </div>

            <div className="conversation-list">
              {filteredConversations.length > 0 ? (
                filteredConversations.map(conversation => {
                  const lastMessage = conversation.lastMessage;
                  let preview = conversation.online ? 'Online agora' : 'Nenhuma mensagem ainda';
                  if (lastMessage) {
                    if (lastMessage.queued && lastMessage.direction === 'in') {
                      preview = `Mensagem recebida: ${lastMessage.text}`;
                    } else if (lastMessage.direction === 'out') {
                      preview = `Você: ${lastMessage.text}`;
                    } else {
                      preview = lastMessage.text;
                    }
                  }

                  return (
                    <button type="button" key={conversation.id} className={`conversation-item ${target === conversation.id ? 'active' : ''}`} onClick={() => openConversation(conversation.id)}>
                      <span className="conversation-avatar">
                        {conversation.id.slice(0, 1).toUpperCase()}
                        <span className={`presence-dot ${conversation.online ? 'is-online' : ''}`} />
                      </span>
                      <span className="conversation-copy">
                        <span className="conversation-topline"><strong title={conversation.id}>{conversation.id}</strong><span className="conversation-time">{lastMessage ? formatTime(lastMessage.timestamp) : ''}</span></span>
                        <span className="conversation-preview">{preview}</span>
                      </span>
                    </button>
                  );
                })
              ) : (
                <div className="conversation-empty">
                  <p>Nenhuma conversa por enquanto.</p>
                </div>
              )}
            </div>
          </section>

          <section className="panel users-panel">
            <div className="section-heading">
              <div><span className="eyebrow">REDE</span><h2>Usuários online</h2></div>
              <span className="count">{users.length}</span>
            </div>
            {users.length ? (
              <ul className="user-list">
                {users.map(id => (
                  <li key={id}>
                    <span className="avatar">{id.slice(0, 1).toUpperCase()}</span>
                    <span className="online-user-name" title={id}>{id}</span>
                    <button className="text-button" onClick={() => openConversation(id)}>Conversar</button>
                  </li>
                ))}
              </ul>
            ) : (<p className="muted">Nenhum outro usuário conectado.</p>)}
          </section>

          <section className="panel group-panel">
            <div className="section-heading">
              <div><span className="eyebrow">ETAPA 03</span><h2>Grupos</h2></div>
            </div>
            {groups.length > 0 && (
              <div className="group-conversation-list">
                <span className="key-label">Seus grupos</span>
                {groups.map(group => (
                  <button key={group.groupID} type="button" className={`group-conversation-item ${activeGroupID === group.groupID ? 'active' : ''}`} onClick={() => openGroup(group.groupID)}>
                    <span className="group-avatar">G</span>
                    <span className="group-conversation-copy">
                      <strong>Grupo {group.groupID.slice(0, 8)}</strong>
                      <small>{group.members.length} participantes</small>
                    </span>
                  </button>
                ))}
              </div>
            )}
            <form onSubmit={createGroup}>
              <label>IDs dos membros separados por vírgula<input value={groupMembers} onChange={e => setGroupMembers(e.target.value)} placeholder="bob, carol" /></label>
              <button className="secondary full-width" disabled={busy || !groupMembers.trim()}>Criar grupo</button>
            </form>
          </section>
        </aside>

        <section className="panel chat-panel">
          <div className="chat-header">
            {activeGroupID ? (
              <>
                <span className="conversation-avatar chat-header-avatar group-avatar">G</span>
                <div className="chat-header-copy">
                  <h2>{groups.find(g => g.groupID === activeGroupID) ? `Grupo ${activeGroupID.slice(0, 8)}` : 'Grupo'}</h2>
                  <span>{groups.find(g => g.groupID === activeGroupID)?.members.length || 0} participantes · mensagens criptografadas</span>
                </div>
              </>
            ) : target ? (
              <>
                <span className="conversation-avatar chat-header-avatar">
                  {target.slice(0, 1).toUpperCase()}
                </span>
                <div className="chat-header-copy">
                  <h2>{target}</h2>
                </div>
              </>
            ) : (
              <div className="chat-header-copy">
                <h2>Mensagens diretas</h2>
                <span>Selecione uma conversa para começar</span>
              </div>
            )}
          </div>

          <div className="message-list" ref={messageListRef}>
            {!target && !activeGroupID ? (
              <div className="empty-state">
                <p>Suas conversas em um só lugar.</p>
              </div>
            ) : activeMessages.length === 0 ? (
              <div className="empty-state">
                <p>Nenhuma mensagem ainda.</p>
              </div>
            ) : (
              activeMessages.map(message => (
                <article key={message.id} className={`message ${message.direction}`}>
                  <span className="message-meta">{message.direction === 'out' ? 'Você' : message.peer} · {formatTime(message.timestamp)}</span>
                  <p>{message.text}</p>
                </article>
              ))
            )}
          </div>

          <form className="composer" onSubmit={sendMessage}>
            <textarea
              value={draft}
              onChange={e => setDraft(e.target.value)}
              placeholder="Digite uma mensagem (Max. 28 bytes)"
              rows={3}
              maxLength={28}
              disabled={(!target && !activeGroupID) || busy || isLocked}
            />
            <div className="composer-footer">
              <span>{new TextEncoder().encode(draft).length}/28 bytes</span>
              <button disabled={busy || (!target && !activeGroupID) || !draft.trim() || new TextEncoder().encode(draft).length > 28 || isLocked}>
                Cifrar e enviar ↗
              </button>
            </div>
          </form>
        </section>
      </div>
    </main>
  );
}