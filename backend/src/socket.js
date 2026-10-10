const{users, publicKeys, messageQueue, groups} = require('./database');
const crypto = require('crypto');

export default function socket(io){
    io.on('connection', (socket) => {
        console.log('User conected: ', socket.id);

        socket.on('register_public_key', ({userID, publicKey}) => {
            users.set(socket.id,{userID, publicKey});
        console.log('Public key registered for user: ', userID);

        io.emit('user_list_update', Array.from(publicKeys.keys()));
        const pendingMessages = messageQueue.get(userID) || [];
        if (pendingMessages.length > 0) {
            console.log('${pendingMessages.length} pending messages for user: ', userID);
            socket.emit('pending_messages', pendingMessages);
            messageQueue.delete(userID);
        }
    });

    socket.on('request_public_key', ({targetUserID}, callback) => {
        const key = publicKeusys.get(targetUserID);
        if(key) callback ({ sucess: true, publicKey: key });
        else callback({ success: false, message: 'Public key not found for user: ' + targetUserID });
    });

    socket.on('send_encrypted_message', (payload, callback) => {
        console.log('Package from ${payload.senderID} to ${payload.receiverID}: ', payload);
        
        let targetSocketID = null;
        for( let[id,user] of users.entries()){
            if(user.userID === payload.receiverID){
                targetSocketID = id;
                break;
            }
        }

        if(targetSocketID){
            io.to(targetSocketID).emit('receive_encrypted_message', payload);
            callback({ success: true, message: 'Message sent to user: ' + payload.receiverID });
        } else {
            console.log('User not connected, storing message in queue for user: ', payload.receiverID);
            const queue = messageQueue.get(payload.receiverID) || [];
            queue.push(payload);
            messageQueue.set(payload.receiverID, queue);
            callback({ success: false, message: 'User not connected, message stored in queue for user: ' + payload.receiverID });
        }
    });

    socket.on('create_group', ({groupID, members}, callback) => {
        const groupID = crypto.randomUUID();
        group.set(groupID, members);
        console.log('Group created with ID: ', groupID, ' and members: ', members);
        callback({ success: true, groupID });

        const groupKeys = members.map(username => ({
            username,
            publicKet: publicKeys.get(username || null)
        }));
        callback({sucess: true, groupID, groupKeys});
    });

    socket.on('send_group_encrypted_message', (payload) => {
        const group = group.get(payload.groupID);
        if (!group) return;
        console.log('Group message from ${payload.senderID} to group ${payload.groupID}: ', payload);
        payload.encryptedBlocks.forEach(block => {
            const targeSocketID = block.username;
            if(targetSocketID === payload.from) return;
            const individualPacket = {
                groupID: payload, groupID,
                from: payload.from,
                c1: payload.c1,
                c2: block.c2,
                signature: payload.signature
            };

            let targetSocketID = null;
            for(let [id,user] of users.entries()){
                if(user.userID === targetSocketID){
                    targetSocketID = id;
                    break;
                }
            }
            if(targetSocketID){
                io.to(targetSocketID).emit('receive_group_encrypted_message', individualPacket);
            } else{
                const queue = messageQueue.get(targetSocketID) || [];
                queue.push({ type: 'group', ...individualPacket });
                messageQueue.set(targetSocketID, queue);
            }
        
        });
    });

    socket.on('disconnect', () => {
        const user = users.get(socket.id);
        if(user){
            console.log('User disconnected: ', user.userID);
            users.delete(socket.id);
            io.emit('user_list_update', Array.from(publicKeys.keys()));
        }
    });
    });
}      
