
const { pool } = require('../config/database');
const { groups } = require('../state/runtimeState');
const { logEvent, logError } = require('../utils/logger');
const {
    compactHexToUuid,
    uuidToCompactHex,
} = require('../utils/identifiers');

async function persistGroup(groupID, group) {
    logEvent('DATABASE', 'Persistindo grupo e membros', { groupID, createdBy: group.createdBy, members: group.members, signature: group.signature });
    const databaseGroupID = compactHexToUuid(groupID);
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        await client.query(
            `
            INSERT INTO groups (
                group_id, created_by, signature, created_at
            )
            VALUES ($1::uuid, $2, $3, NOW())
            `,
            [
                databaseGroupID,
                group.createdBy,
                group.signature,
            ]
        );

        for (const memberID of group.members) {
            await client.query(
                `
                INSERT INTO group_members (
                    group_id, user_id, joined_at
                )
                VALUES ($1::uuid, $2, NOW())
                `,
                [databaseGroupID, memberID]
            );
        }

        await client.query('COMMIT');
        logEvent('DATABASE', 'Grupo persistido com sucesso', { groupID, createdBy: group.createdBy, memberCount: group.members.length });
    } catch (error) {
        await client.query('ROLLBACK');
        logError('DATABASE', 'Transação de grupo revertida', error, { groupID });
        throw error;
    } finally {
        client.release();
    }
}

let persistedGroupsLoadPromise = null;

async function loadPersistedGroups() {
    logEvent('DATABASE', 'Solicitação para carregar grupos persistidos');
    if (persistedGroupsLoadPromise) {
        return persistedGroupsLoadPromise;
    }

    persistedGroupsLoadPromise = (async () => {
        const result = await pool.query(
            `
            SELECT
                g.group_id,
                g.created_by,
                g.signature,
                gm.user_id
            FROM groups g
            LEFT JOIN group_members gm
                ON gm.group_id = g.group_id
            ORDER BY g.created_at ASC, gm.user_id ASC
            `
        );

        const loadedGroups = new Map();

        for (const row of result.rows) {
            const groupID = uuidToCompactHex(row.group_id);

            if (!loadedGroups.has(groupID)) {
                loadedGroups.set(groupID, {
                    members: [],
                    createdBy: row.created_by,
                    signature: row.signature,
                });
            }

            if (row.user_id) {
                loadedGroups.get(groupID).members.push(row.user_id);
            }
        }

        groups.clear();

        for (const [groupID, group] of loadedGroups) {
            groups.set(groupID, group);
        }

        logEvent('DATABASE', 'Grupos carregados do PostgreSQL', { count: groups.size, groups: [...groups.entries()].map(([groupID, group]) => ({ groupID, ...group })) });
    })();

    try {
        await persistedGroupsLoadPromise;
    } catch (error) {
        persistedGroupsLoadPromise = null;
        throw error;
    }
}

module.exports = {
    persistGroup,
    loadPersistedGroups,
};
