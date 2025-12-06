import WebSocket from 'ws';
import http from 'http';
import { setupWSConnection, docs } from './utils.js';
import axios from 'axios';
// @ts-ignore
import jwt from 'jsonwebtoken';
import { parse } from 'url';
import dotenv from 'dotenv';
dotenv.config();

const clientsByDoc = new Map(); // Yjs document connections
const globalCollabClients = new Map(); // userId -> Set of WebSocket connections

const server = http.createServer((request, response) => {
  console.log('📥 HTTP request:', request.method, request.url);
  
  // Handle collaborator event broadcasting
  if (request.method === 'POST' && request.url === '/collab-event') {
    console.log('🎯 /collab-event endpoint hit!');
    let body = '';
    request.on('data', chunk => body += chunk.toString());
    request.on('end', () => {
      console.log('📦 Collab event body:', body);
      try {
        const msg = JSON.parse(body);
        const { docId, type, payload } = msg;
        
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('📡 Broadcasting collaborator event');
        console.log('   Type:', type);
        console.log('   DocId:', docId);
        console.log('   Payload:', payload);
        
        // Broadcast to all global collaborator connections
        broadcastCollabEvent(docId, type, payload);
        
        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({ 
          ok: true, 
          recipientCount: globalCollabClients.size 
        }));
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      } catch (e) {
        console.error('❌ Parse error:', e);
        response.writeHead(400);
        response.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }
  
  response.writeHead(200, { 'Content-Type': 'text/plain' });
  response.end('okay');
});

// Create WebSocket server with noServer option
const wss = new WebSocket.Server({ noServer: true });

// Track connections per document
const connectionCounts = new Map(); // docId -> count
const connectionTimers = new Map(); // docId -> setTimeout reference

const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-key';

/**
 * Broadcast collaborator events to all connected users
 */
function broadcastCollabEvent(docId, type, payload) {
  const message = JSON.stringify({ docId, type, payload });
  let sentCount = 0;

  // Determine recipients
  let recipients = [];
  
  if (payload.recipients && Array.isArray(payload.recipients)) {
    // Use explicit recipients list
    recipients = payload.recipients;
  } else if (payload._id) {
    // For collaborator-removed, notify the removed user
    recipients = [payload._id];
  } else if (payload.userId) {
    // For permission-updated, notify the affected user
    recipients = [payload.userId];
  }

  console.log('   Target recipients:', recipients);

  if (recipients.length === 0) {
    console.log('   ⚠️ No recipients specified, broadcasting to ALL');
    // Broadcast to everyone if no specific recipients
    // @ts-ignore
    globalCollabClients.forEach((connections, userId) => {
      connections.forEach(ws => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(message);
          sentCount++;
        }
      });
    });
  } else {
    // Broadcast only to specific recipients
    recipients.forEach(userId => {
      const userConnections = globalCollabClients.get(userId);
      
      if (userConnections && userConnections.size > 0) {
        userConnections.forEach(ws => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(message);
            sentCount++;
          }
        });
        console.log(`✓ Sent to user ${userId} (${userConnections.size} connections)`);
      } else {
        console.log(`⚠️ User ${userId} not connected`);
      }
    });
  }

  console.log(`📤 Total messages sent: ${sentCount}`);
  return sentCount;
}

/**
 * Authenticate function - validates JWT token and document permission
 */
async function authenticate(accessToken, docName) {
  try {
    console.log(`[AUTH] Attempting to authenticate for document: ${docName}`);
    
    if (!accessToken) {
      console.log('[AUTH] No access token provided');
      return { authenticated: false, userId: null };
    }

    // Verify JWT token
    let decoded;
    try {
      decoded = jwt.verify(accessToken, JWT_SECRET);
      const userId = decoded.userId || decoded.id;
      console.log('[AUTH] Token verified for user:', userId);
    } catch (err) {
      // @ts-ignore
      console.log('[AUTH] Invalid token:', err.message);
      return { authenticated: false, userId: null };
    }

    const userId = decoded.userId || decoded.id;

    // If it's a global collab connection, just verify the token
    if (docName === 'global') {
      return { authenticated: true, userId };
    }

    // For document-specific connections, check permissions
    const documentId = docName.replace('doc-', '');
    
    try {
      const response = await axios.get(
        `${API_BASE_URL}/api/documents/${documentId}/permission`,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          },
          timeout: 5000
        }
      );

      const hasPermission = response.data.permission === 'edit' || response.data.permission === 'view';
      console.log(`[AUTH] User ${userId} permission for ${documentId}: ${hasPermission}`);
      
      return { authenticated: hasPermission, userId };
    } catch (err) {
      // @ts-ignore
      console.log('[AUTH] Permission check failed:', err.message);
      return { authenticated: false, userId };
    }
  } catch (error) {
    console.error('[AUTH] Authentication error:', error);
    return { authenticated: false, userId: null };
  }
}

/**
 * Handle HTTP upgrade to WebSocket
 */
server.on('upgrade', async (request, socket, head) => {
  // @ts-ignore
  const { pathname, query } = parse(request.url, true);
  const token = query.token;
  
  console.log(`[UPGRADE] Path: ${pathname}`);
  
  let isGlobalCollabWS = false;
  let docName = null;

  // Determine connection type
  if (pathname === '/collab-global') {
    isGlobalCollabWS = true;
    docName = 'global';
    console.log('[UPGRADE] Global collaborator WebSocket connection');
  } else if (pathname?.startsWith('/collab/')) {
    // Document-specific collab connection (not used currently, but supported)
    docName = 'doc-' + pathname.slice('/collab/'.length).split('?')[0];
    console.log('[UPGRADE] Document collaborator WebSocket connection:', docName);
  } else {
    // Yjs document connection
    docName = pathname?.slice(1).split('?')[0];
    console.log('[UPGRADE] Yjs document connection:', docName);
  }

  // Authenticate
  const { authenticated, userId } = await authenticate(token, docName);
  
  if (!authenticated) {
    console.log('[UPGRADE] Authentication failed, rejecting connection');
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }

  console.log('[UPGRADE] Authentication successful, upgrading connection');

  // Upgrade to WebSocket
  wss.handleUpgrade(request, socket, head, ws => {
    // @ts-ignore
    ws.isGlobalCollabWS = isGlobalCollabWS;
    // @ts-ignore
    ws.userId = userId;
    // @ts-ignore
    ws.docName = docName;
    wss.emit('connection', ws, request);
  });
});

/**
 * Handle WebSocket connections
 */
wss.on('connection', (conn, req) => {
  // @ts-ignore
  const { pathname } = parse(req.url, true);

  // Handle global collaborator WebSocket
  // @ts-ignore
  if (conn.isGlobalCollabWS) {
    // @ts-ignore
    const userId = conn.userId;
    
    console.log(`🌍 Global collaborator WS connected for user: ${userId}`);
    
    // Store connection by userId
    if (!globalCollabClients.has(userId)) {
      globalCollabClients.set(userId, new Set());
    }
    globalCollabClients.get(userId).add(conn);
    
    console.log(`   User ${userId} now has ${globalCollabClients.get(userId).size} global connections`);
    console.log(`   Total users with global connections: ${globalCollabClients.size}`);

    conn.on('close', () => {
      if (globalCollabClients.has(userId)) {
        globalCollabClients.get(userId).delete(conn);
        if (globalCollabClients.get(userId).size === 0) {
          globalCollabClients.delete(userId);
        }
      }
      console.log(`🌍 Global collaborator WS disconnected for user: ${userId}`);
    });

    conn.on('error', (error) => {
      console.error(`❌ Global collab WS error for user ${userId}:`, error);
    });

    return;
  }

  // Handle Yjs document connection
  // @ts-ignore
  const docName = conn.docName;
  const docId = docName.replace('doc-', '');
  
  console.log(`📝 Yjs connection established for document: ${docId}`);

  if (!clientsByDoc.has(docId)) {
    clientsByDoc.set(docId, new Set());
  }
  clientsByDoc.get(docId).add(conn);
  
  // Increment connection count
  const currentCount = connectionCounts.get(docId) || 0;
  connectionCounts.set(docId, currentCount + 1);
  
  console.log(`[${docId}] User connected. Active connections: ${connectionCounts.get(docId)}`);
  
  // Clear any pending save timer
  if (connectionTimers.has(docId)) {
    clearTimeout(connectionTimers.get(docId));
    connectionTimers.delete(docId);
  }
  
  // Setup WebSocket connection with Yjs
  setupWSConnection(conn, req, { docName });
  
  // Handle disconnect
  conn.on('close', async () => {
    if (clientsByDoc.has(docId)) {
      clientsByDoc.get(docId).delete(conn);
      if (clientsByDoc.get(docId).size === 0) {
        clientsByDoc.delete(docId);
      }
    }

    const count = (connectionCounts.get(docId) || 1) - 1;
    connectionCounts.set(docId, count);
    
    console.log(`[${docId}] User disconnected. Remaining connections: ${count}`);
    
    // If last connection, schedule save
    if (count === 0) {
      console.log(`[${docId}] Last user disconnected. Scheduling save in 2 seconds...`);
      
      const timer = setTimeout(async () => {
        if (connectionCounts.get(docId) === 0) {
          await saveDocumentToBackend(docName, docId);
          connectionCounts.delete(docId);
          connectionTimers.delete(docId);
        }
      }, 2000);
      
      connectionTimers.set(docId, timer);
    }
  });
  
  conn.on('error', (error) => {
    console.error(`[${docId}] WebSocket error:`, error);
  });
});

/**
 * Save document content to backend when all users disconnect
 */
async function saveDocumentToBackend(docName, docId) {
  try {
    console.log(`[${docId}] Saving document to backend...`);
    
    const ydoc = docs.get(docName);
    if (!ydoc) {
      console.error(`[${docId}] Yjs document not found`);
      return;
    }
    
    const ytext = ydoc.getText('codemirror');
    const content = ytext.toString();
    
    console.log(`[${docId}] Content length: ${content.length} characters`);
    
    const response = await axios.post(`${API_BASE_URL}/api/documents/save`, {
      documentId: docId,
      content: content
    }, {
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    console.log(`[${docId}] ✓ Successfully saved to backend`);
    return response.data;
  } catch (error) {
    // @ts-ignore
    console.error(`[${docId}] ✗ Error saving to backend:`, error.message);
    // @ts-ignore
    if (error.response) {
      // @ts-ignore
      console.error(`[${docId}] Backend response:`, error.response.data);
    }
  }
}

const PORT = process.env.PORT || 1234;
server.listen(PORT, () => {
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`✓ WebSocket server running on ws://localhost:${PORT}`);
  console.log(`✓ API backend: ${API_BASE_URL}`);
  console.log(`✓ JWT authentication enabled`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  
  const savePromises = Array.from(docs.keys()).map(docName => {
    const docId = docName.replace('doc-', '');
    return saveDocumentToBackend(docName, docId);
  });
  
  await Promise.all(savePromises);
  console.log('✓ All documents saved. Exiting.');
  process.exit(0);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
});

// @ts-ignore
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection:', reason);
});