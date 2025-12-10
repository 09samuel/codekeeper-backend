# CodeKeeper WebSocket Backend

Real-time collaboration server for CodeKeeper, built on Yjs WebSocket infrastructure. Handles live document synchronization, user presence, and conflict-free collaborative editing using CRDT technology.

🔗 **Main Project:** [CodeKeeper](https://github.com/09samuel/codekeeper)


>**Note:** This project is forked from [yjs/y-websocket-server](https://github.com/yjs/y-websocket-server) and customized for CodeKeeper's specific requirements.

## Overview

This backend provides the WebSocket server infrastructure that powers real-time collaborative editing in CodeKeeper. It implements Yjs protocol for efficient document synchronization with support for multiple concurrent users and persistent document storage.


## Customizations & Enhancements

- JWT authentication integration with CodeKeeper API
- Custom authentication middleware for secure connections
- MongoDB persistence layer integration
- Custom logging and monitoring
- Production deployment optimizations


## Features

- **Real-Time Synchronization** - Sub-100ms latency for collaborative editing
- **CRDT-Based Conflict Resolution** - Automatic merging of concurrent edits using Yjs
- **User Authentication** - JWT-based authentication for secure connections
- **Document Persistence** - Automatic document state management
- **Presence Awareness** - Live cursor tracking and user presence information
- **Scalable Architecture** - Handles multiple concurrent editing sessions

## Tech Stack

- **Node.js** (>= 16.0.0) - JavaScript runtime
- **Yjs** (v14.0.0) - CRDT framework for conflict-free replicated data types
- **WebSocket (ws)** - Real-time bidirectional communication protocol
- **TypeScript** - Type-safe development with compilation support
- **JWT** - Secure token-based authentication
- **Axios** - HTTP client for external API communication