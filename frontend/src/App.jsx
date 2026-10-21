import { useEffect, useMemo, useRef, useState } from 'react';
import {
  createIdentity,
  encryptForRecipient,
  decryptAndVerify,
  publicFromPrivate,
  validatePrivateKey,
  encryptForGroup,
  decryptGroupAndVerify,
} from './crypto';
import { createSocket, emitAck } from './socket';

const STORAGE_KEY = 'ecdh-chat.identity.v1';

const readIdentity = () => {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
  } catch {
    return null;
  }
};

function formatTime(timestamp) {
  if (!timestamp) return '';

  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) return '';

  const today = new Date();
  const isToday = date.toDateString() === today.toDateString();

  if (isToday) {
    return date.toLocaleTimeString('pt-BR', {
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  return date.toLocaleDateString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
  });
}

function getLastMessage(messages, userID) {
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].peer === userID) {
      return messages[i];
    }
  }

  return null;
}

export default function App() {
  const socket = useMemo(() => createSocket(), []);

  const [identity, setIdentity] = useState(readIdentity);
  const [userID, setUserID] = useState(readIdentity()?.userID || '');
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
  const targetRef = useRef(target);
  const messageListRef = useRef(null);

  useEffect(() => {
    identityRef.current = identity;
  }, [identity]);

  useEffect(() => {
    userRef.current = userID;
  }, [userID]);

  useEffect(() => {
    targetRef.current = target;
  }, [target]);

  // Lista os contatos conhecidos pela sessão e organiza as conversas.
  
  const conversations = useMemo(() => {
    // Considera somente mensagens diretas, excluindo mensagens de grupo.
    const directMessages = messages.filter(
      message => !message.groupID && message.type !== 'group'
    );

    const contactIDs = new Set(users);

    directMessages.forEach(message => {
      if (message.peer) {
        contactIDs.add(message.peer);
      }
    });

    contactIDs.delete(identity?.userID || userID);

    return Array.from(contactIDs)
      .map(id => {
        // A última mensagem é buscada somente no histórico direto.
        const lastMessage = getLastMessage(directMessages, id);

        return {
          id,
          lastMessage,
          lastTimestamp: lastMessage?.timestamp || 0,
          online: users.includes(id),
        };
      })
      .sort((a, b) => {
        // Conversas com mensagens mais recentes ficam no topo.
        if (a.lastTimestamp !== b.lastTimestamp) {
          return b.lastTimestamp - a.lastTimestamp;
        }

        // Sem mensagens, contatos online aparecem primeiro.
        if (a.online !== b.online) {
          return Number(b.online) - Number(a.online);
        }

        return a.id.localeCompare(b.id);
      });
  }, [users, messages, identity, userID]);


  const filteredConversations = useMemo(() => {
    const query = conversationSearch.trim().toLocaleLowerCase('pt-BR');

    if (!query) return conversations;

    return conversations.filter(conversation =>
      conversation.id.toLocaleLowerCase('pt-BR').includes(query)
    );
  }, [conversations, conversationSearch]);

  const activeMessages = useMemo(() => {
    if (activeGroupID) {
      return messages.filter(message => message.groupID === activeGroupID);
    }

    return messages.filter(
      message => !message.groupID && message.peer === target
    );
  }, [messages, target, activeGroupID]);

  const selectedConversation = conversations.find(
    conversation => conversation.id === target
  );

  // Mantém a conversa aberta posicionada na mensagem mais recente.
  useEffect(() => {
    const element = messageListRef.current;

    if (element) {
      element.scrollTop = element.scrollHeight;
    }
  }, [activeMessages, target]);

  useEffect(() => {
    socket.on('connect', () => setStatus('Conectado'));
    socket.on('disconnect', () => setStatus('Desconectado'));

    socket.on('connect_error', err => {
      setNotice(`Falha de conexão: ${err.message}`);
    });

    socket.on('user_list_update', list => {
      setUsers(
        Array.isArray(list)
          ? list.filter(id => id !== userRef.current)
          : []
      );
    });

    socket.on('receive_encrypted_message', packet => {
      handleIncoming(packet);
    });

    socket.on('receive_group_encrypted_message', packet => {
      handleIncomingGroup(packet);
    });

    socket.on('your_groups', groupList => {
      setGroups(Array.isArray(groupList) ? groupList : []);
    });

    socket.on('group_created', groupData => {
      setGroups(previous => [
        ...previous.filter(group => group.groupID !== groupData.groupID),
        groupData,
      ]);
    });

    socket.on('pending_messages', (packets, ack) => {
      Promise.all(
        (packets || []).map(packet =>
          packet.type === 'group'
            ? handleIncomingGroup(packet, true)
            : handleIncoming(packet, true)
        )
      ).finally(() => {
        if (typeof ack === 'function') ack();
      });
    });

    return () => {
      socket.removeAllListeners();
      socket.disconnect();
    };

    // Os listeners são registrados uma vez; os handlers usam refs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function register(id, ident) {
    const normalizedID = id.trim();

    if (!normalizedID) {
      throw new Error('Informe um identificador de usuário.');
    }

    const response = await emitAck(socket, 'register_public_key', {
      userID: normalizedID,
      publicKey: ident.publicKey,
    });

    if (!response.success) {
      throw new Error(response.message || 'Registro recusado.');
    }

    const next = { ...ident, userID: normalizedID };

    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));

    setIdentity(next);
    identityRef.current = next;

    setUserID(normalizedID);
    userRef.current = normalizedID;

    setNotice(
      'Identidade registrada. A chave privada permanece neste navegador.'
    );
  }

  async function ensureConnected() {
    if (socket.connected) return;

    await new Promise((resolve, reject) => {
      const onConnect = () => {
        cleanup();
        resolve();
      };

      const onError = error => {
        cleanup();
        reject(error);
      };

      const cleanup = () => {
        socket.off('connect', onConnect);
        socket.off('connect_error', onError);
      };

      socket.once('connect', onConnect);
      socket.once('connect_error', onError);
      socket.connect();
    });
  }

  async function createNewIdentity() {
    setBusy(true);

    try {
      const id = userID.trim();

      if (!id) {
        throw new Error('Informe o identificador antes de gerar a identidade.');
      }

      await ensureConnected();

      const ident = createIdentity();
      await register(id, ident);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function reconnect() {
    setBusy(true);

    try {
      if (!identity) {
        throw new Error('Crie ou importe uma identidade primeiro.');
      }

      await ensureConnected();
      await register(userID || identity.userID, identity);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function importIdentity() {
    setBusy(true);

    try {
      const privateKey = privateImport.trim().toLowerCase();

      validatePrivateKey(privateKey);

      const imported = {
        privateKey,
        publicKey: publicFromPrivate(privateKey),
      };

      await ensureConnected();
      await register(userID, imported);

      setPrivateImport('');
    } catch (error) {
      setNotice(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleIncoming(packet, queued = false) {
    try {
      const me = identityRef.current;

      if (!me || packet.receiverID !== me.userID) return;

      const key = await emitAck(socket, 'request_public_key', {
        targetUserID: packet.senderID,
      });

      if (!key.success) {
        throw new Error('Não foi possível obter a chave pública do remetente.');
      }

      const plaintext = decryptAndVerify(
        packet,
        me.privateKey,
        key.publicKey
      );

      setMessages(previous => [
        ...previous,
        {
          id: `${packet.timestamp}-${Math.random()}`,
          direction: 'in',
          peer: packet.senderID,
          text: plaintext,
          timestamp: packet.timestamp || Date.now(),
          queued,
        },
      ]);
    } catch (error) {
      setNotice(`Mensagem recebida rejeitada: ${error.message}`);
    }
  }

  async function handleIncomingGroup(packet) {
    try {
      const me = identityRef.current;

      if (!me || packet.receiverID !== me.userID) return;

      const key = await emitAck(socket, 'request_public_key', {
        targetUserID: packet.senderID,
      });

      if (!key.success) {
        throw new Error('Não foi possível obter a chave pública do remetente.');
      }

      const plaintext = decryptGroupAndVerify(
        packet,
        me.privateKey,
        key.publicKey,
        me.userID
      );

      setMessages(previous => [
        ...previous,
        {
          id: `${packet.timestamp}-${Math.random()}`,
          type: 'group',
          groupID: packet.groupID,
          peer: packet.senderID,
          direction: 'in',
          text: plaintext,
          timestamp: packet.timestamp || Date.now(),
        },
      ]);
    } catch (error) {
      setNotice(`Mensagem de grupo rejeitada: ${error.message}`);
    }
  }

  async function sendMessage(event) {
    event.preventDefault();
    if (activeGroupID) {
      setBusy(true);

      try {
        await sendGroupMessage();
      } catch (error) {
        setNotice(error.message);
      } finally {
        setBusy(false);
      }

      return;
    }

    setBusy(true);

    try {
      const me = identityRef.current;
      const recipient = targetRef.current;

      if (!me) {
        throw new Error('Registre uma identidade primeiro.');
      }

      if (!recipient || recipient === me.userID) {
        throw new Error('Escolha outro usuário.');
      }

      if (!draft.trim()) {
        throw new Error('Digite uma mensagem.');
      }

      const byteLength = new TextEncoder().encode(draft).length;

      if (byteLength > 28) {
        throw new Error('A mensagem ultrapassa o limite de 28 bytes UTF-8.');
      }

      const key = await emitAck(socket, 'request_public_key', {
        targetUserID: recipient,
      });

      if (!key.success) {
        throw new Error(
          key.message || 'Chave pública do destinatário indisponível.'
        );
      }

      const packet = encryptForRecipient(
        draft,
        key.publicKey,
        me.privateKey,
        me.userID,
        recipient
      );

      const response = await emitAck(
        socket,
        'send_encrypted_message',
        packet
      );

      if (!response.success) {
        throw new Error(response.message || 'Envio recusado.');
      }

      setMessages(previous => [
        ...previous,
        {
          id: `${Date.now()}-out-${Math.random()}`,
          direction: 'out',
          peer: recipient,
          text: draft,
          timestamp: Date.now(),
        },
      ]);

      setDraft('');

      setNotice(
        response.delivered
          ? 'Mensagem cifrada encaminhada.'
          : 'Mensagem cifrada armazenada na fila offline.'
      );
    } catch (error) {
      setNotice(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function sendGroupMessage() {
    const me = identityRef.current;
    const group = groups.find(item => item.groupID === activeGroupID);

    if (!me) {
      throw new Error('Registre uma identidade primeiro.');
    }

    if (!group) {
      throw new Error('Grupo não encontrado nesta sessão.');
    }

    if (!draft.trim()) {
      throw new Error('Digite uma mensagem.');
    }

    const byteLength = new TextEncoder().encode(draft).length;

    if (byteLength > 28) {
      throw new Error('A mensagem ultrapassa o limite de 28 bytes UTF-8.');
    }

    const encryptedPacket = encryptForGroup(
      draft,
      group.groupID,
      group.groupKeys,
      me.privateKey,
      me.userID
    );

    const response = await emitAck(
      socket,
      'send_group_encrypted_message',
      encryptedPacket
    );

    if (!response.success) {
      throw new Error(response.message || 'Envio da mensagem de grupo recusado.');
    }

    setMessages(previous => [
      ...previous,
      {
        id: `${Date.now()}-group-out-${Math.random()}`,
        type: 'group',
        groupID: group.groupID,
        peer: me.userID,
        direction: 'out',
        text: draft,
        timestamp: Date.now(),
      },
    ]);

    setDraft('');

    setNotice(
      `Mensagem de grupo encaminhada. Entregues: ${response.delivered || 0}; na fila: ${response.queued || 0}; falhas: ${response.failed || 0}.`
    );
  }

  async function createGroup(event) {
    event.preventDefault();
    setBusy(true);

    try {
      const members = groupMembers
        .split(',')
        .map(value => value.trim())
        .filter(Boolean);

      const response = await emitAck(socket, 'create_group', { members });

      if (!response.success) {
        throw new Error(response.message || 'Não foi possível criar o grupo.');
      }

      const newGroup = {
        groupID: response.groupID,
        members: response.members,
        groupKeys: response.groupKeys,
        createdBy: response.createdBy || identityRef.current?.userID,
      };

      setGroups(previous => [
        ...previous.filter(group => group.groupID !== newGroup.groupID),
        newGroup,
      ]);

      setTarget('');
      targetRef.current = '';
      setActiveGroupID(newGroup.groupID);
      setGroupID(newGroup.groupID);
      setGroupMembers('');

      setNotice(
        `Grupo criado com ${newGroup.members.length} participantes. A cifragem de grupo está disponível.`
      );
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
  }

  function openGroup(groupID) {
    setTarget('');
    targetRef.current = '';
    setActiveGroupID(groupID);
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand-mark">E</div>

        <div>
          <h1>ECDH-Chat</h1>
          <p>Mensagens com criptografia de curva elíptica</p>
        </div>

        <span className={`connection ${status === 'Conectado' ? 'online' : ''}`}>
          {status}
        </span>
      </header>

      {notice && (
        <div className="notice" role="status">
          <span>{notice}</span>
          <button
            className="icon-button"
            onClick={() => setNotice('')}
            aria-label="Fechar aviso"
          >
            ×
          </button>
        </div>
      )}

      <section className="panel identity-panel">
        <div className="section-heading">
          <div>
            <span className="eyebrow">ETAPA 01</span>
            <h2>Sua identidade</h2>
          </div>

          <span className="pill">secp256k1 · ECDSA</span>
        </div>

        <div className="identity-grid">
          <label>
            Identificador de usuário
            <input
              value={userID}
              onChange={event => setUserID(event.target.value)}
              placeholder="ex.: alice"
              maxLength={128}
            />
          </label>

          <div className="button-row">
            <button
              onClick={createNewIdentity}
              disabled={busy || !userID.trim()}
            >
              Gerar identidade
            </button>

            <button
              className="secondary"
              onClick={reconnect}
              disabled={busy || !identity}
            >
              Conectar / registrar
            </button>
          </div>
        </div>

        {identity && (
          <div className="key-card">
            <div>
              <span className="key-label">Identidade local</span>
              <strong>{identity.userID || userID || 'Não registrada'}</strong>
            </div>

            <div>
              <span className="key-label">Chave pública</span>
              <code>{identity.publicKey}</code>
            </div>

            <p>
              A chave privada é mantida no armazenamento local deste navegador.
              Para uma aplicação real, implemente armazenamento protegido e
              recuperação segura.
            </p>
          </div>
        )}

        <details className="import-details">
          <summary>Importar chave privada existente</summary>

          <label>
            Chave privada hexadecimal (32 bytes)
            <input
              value={privateImport}
              onChange={event => setPrivateImport(event.target.value)}
              placeholder="64 caracteres hexadecimais"
              autoComplete="off"
            />
          </label>

          <button
            className="secondary"
            onClick={importIdentity}
            disabled={busy || !privateImport.trim()}
          >
            Importar e registrar
          </button>
        </details>
      </section>

      <div className="content-grid">
        <aside className="side-column">
          <section className="panel conversations-panel">
            <div className="section-heading">
              <div>
                <span className="eyebrow">MENSAGENS</span>
                <h2>Conversas</h2>
              </div>

              <span className="count">{conversations.length}</span>
            </div>

            <div className="conversation-search">
              <span aria-hidden="true">⌕</span>
              <input
                type="search"
                value={conversationSearch}
                onChange={event => setConversationSearch(event.target.value)}
                placeholder="Buscar conversas..."
                aria-label="Buscar conversas por identificador"
              />

              {conversationSearch && (
                <button
                  className="search-clear"
                  type="button"
                  onClick={() => setConversationSearch('')}
                  aria-label="Limpar busca"
                >
                  ×
                </button>
              )}
            </div>

            <div className="conversation-list">
              {filteredConversations.length > 0 ? (
                filteredConversations.map(conversation => {
                  const lastMessage = conversation.lastMessage;

                  let preview = conversation.online
                    ? 'Online agora'
                    : 'Nenhuma mensagem ainda';

                  if (lastMessage) {
                    preview = lastMessage.direction === 'out'
                      ? `Você: ${lastMessage.text}`
                      : lastMessage.text;

                    if (lastMessage.queued) {
                      preview = `Mensagem recebida: ${lastMessage.text}`;
                    }
                  }

                  return (
                    <button
                      type="button"
                      key={conversation.id}
                      className={`conversation-item ${
                        target === conversation.id ? 'active' : ''
                      }`}
                      onClick={() => openConversation(conversation.id)}
                    >
                      <span className="conversation-avatar">
                        {conversation.id.slice(0, 1).toUpperCase()}
                        <span
                          className={`presence-dot ${
                            conversation.online ? 'is-online' : ''
                          }`}
                        />
                      </span>

                      <span className="conversation-copy">
                        <span className="conversation-topline">
                          <strong title={conversation.id}>
                            {conversation.id}
                          </strong>

                          <span className="conversation-time">
                            {lastMessage
                              ? formatTime(lastMessage.timestamp)
                              : ''}
                          </span>
                        </span>

                        <span className="conversation-preview">
                          {preview}
                        </span>
                      </span>
                    </button>
                  );
                })
              ) : (
                <div className="conversation-empty">
                  <span className="conversation-empty-icon">⌕</span>

                  <p>
                    {conversationSearch
                      ? 'Nenhum contato encontrado.'
                      : 'Nenhuma conversa por enquanto.'}
                  </p>

                  <span>
                    {conversationSearch
                      ? 'Experimente outro identificador.'
                      : 'Quando usuários se conectarem ou você receber mensagens, eles aparecerão aqui.'}
                  </span>
                </div>
              )}
            </div>
          </section>

          <section className="panel users-panel">
            <div className="section-heading">
              <div>
                <span className="eyebrow">REDE</span>
                <h2>Usuários online</h2>
              </div>

              <span className="count">{users.length}</span>
            </div>

            {users.length ? (
              <ul className="user-list">
                {users.map(id => (
                  <li key={id}>
                    <span className="avatar">
                      {id.slice(0, 1).toUpperCase()}
                    </span>

                    <span className="online-user-name" title={id}>
                      {id}
                    </span>

                    <button
                      className="text-button"
                      onClick={() => openConversation(id)}
                    >
                      Conversar
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">Nenhum outro usuário conectado.</p>
            )}
          </section>

          <section className="panel group-panel">
            <div className="section-heading">
              <div>
                <span className="eyebrow">ETAPA 03</span>
                <h2>Grupos</h2>
              </div>
            </div>

            {groups.length > 0 && (
              <div className="group-conversation-list">
                <span className="key-label">Seus grupos</span>

                {groups.map(group => (
                  <button
                    key={group.groupID}
                    type="button"
                    className={`group-conversation-item ${
                      activeGroupID === group.groupID ? 'active' : ''
                    }`}
                    onClick={() => openGroup(group.groupID)}
                  >
                    <span className="group-avatar">G</span>

                    <span className="group-conversation-copy">
                      <strong>
                        Grupo {group.groupID.slice(0, 8)}
                      </strong>
                      <small>{group.members.length} participantes</small>
                    </span>
                  </button>
                ))}
              </div>
            )}

            <form onSubmit={createGroup}>
              <label>
                IDs dos membros separados por vírgula
                <input
                  value={groupMembers}
                  onChange={event => setGroupMembers(event.target.value)}
                  placeholder="bob, carol"
                />
              </label>

              <button
                className="secondary full-width"
                disabled={busy || !groupMembers.trim()}
              >
                Criar grupo
              </button>
            </form>

            {groupID && (
              <div className="group-result">
                <span className="key-label">ID do grupo</span>
                <code>{groupID}</code>
              </div>
            )}

            <p className="muted small">
              A criação e o roteamento do grupo existem no servidor. A cifragem
              multi-destinatário ainda não está implementada nesta interface.
            </p>
          </section>
        </aside>

        <section className="panel chat-panel">
          <div className="chat-header">
            {activeGroupID ? (
              <>
                <span className="conversation-avatar chat-header-avatar group-avatar">
                  G
                </span>

                <div className="chat-header-copy">
                  <h2>
                    {groups.find(group => group.groupID === activeGroupID)
                      ? `Grupo ${activeGroupID.slice(0, 8)}`
                      : 'Grupo'}
                  </h2>

                  <span>
                    {groups.find(group => group.groupID === activeGroupID)?.members.length || 0}
                    {' participantes · mensagens criptografadas'}
                  </span>
                </div>
              </>
            ) : target ? (
              <>
                <span className="conversation-avatar chat-header-avatar">
                  {target.slice(0, 1).toUpperCase()}
                  <span
                    className={`presence-dot ${
                      selectedConversation?.online ? 'is-online' : ''
                    }`}
                  />
                </span>

                <div className="chat-header-copy">
                  <h2>{target}</h2>
                  <span>
                    {selectedConversation?.online
                      ? 'Online'
                      : 'Contato conhecido nesta sessão'}
                  </span>
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
                <div className="empty-icon">☏</div>
                <p>Suas conversas em um só lugar.</p>
                <span>
                  Escolha um contato na lista ao lado para abrir uma conversa.
                </span>
              </div>
            ) : activeMessages.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">↗</div>
                <p>Nenhuma mensagem com {target}.</p>
                <span>
                  Envie a primeira mensagem. O servidor encaminha o pacote
                  cifrado, não o texto original.
                </span>
              </div>
            ) : (
              activeMessages.map(message => (
                <article
                  key={message.id}
                  className={`message ${message.direction}`}
                >
                  <span className="message-meta">
                    {message.direction === 'out' ? 'Você' : message.peer}
                    {' · '}
                    {formatTime(message.timestamp)}
                  </span>

                  <p>{message.text}</p>

                  {message.queued && (
                    <span className="message-status">Recebida da fila offline</span>
                  )}
                </article>
              ))
            )}
          </div>

          <form className="composer" onSubmit={sendMessage}>
            <textarea
              value={draft}
              onChange={event => setDraft(event.target.value)}
              placeholder={
                activeGroupID
                  ? 'Digite uma mensagem para o grupo...'
                  : target
                    ? 'Digite uma mensagem curta...'
                    : 'Selecione uma conversa primeiro'
              }
              rows={3}
              maxLength={28}
              disabled={(!target && !activeGroupID) || busy}
            />

            <div className="composer-footer">
              <span>{new TextEncoder().encode(draft).length}/28 bytes</span>

              <button
                disabled={
                  busy ||
                  (!target && !activeGroupID) ||
                  !draft.trim() ||
                  new TextEncoder().encode(draft).length > 28
                }
              >
                Cifrar e enviar ↗
              </button>
            </div>
          </form>
        </section>
      </div>

      <footer>
        Protótipo acadêmico · Não utilizar para comunicação sensível ou produção.
      </footer>
    </main>
  );
}
