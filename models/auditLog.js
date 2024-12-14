const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    action: {
      type: String,
      enum: ['update', 'delete', 'create'],
      required: true,
    },
    field: {
      type: String,
      required: true,
    },
    previousValue: {
      type: mongoose.Schema.Types.Mixed,
    },
    newValue: {
      type: mongoose.Schema.Types.Mixed,
    },
    ipAddress: {
      type: String,
      required: true,
    },
    timestamp: {
      type: Date,
      default: Date.now,
    },
  });
  
const AuditLog = mongoose.model('AuditLog', auditLogSchema);
module.exports = AuditLog;