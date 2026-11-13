'use strict';
// The license feature names and the two products they are sold as. This must match src/licensing/bundles.js in the ASIX product repo: run
//   node license-vendor.js check-features --product /path/to/ash-app-builder
// after every ASIX release (and before issuing licenses for a new feature) to see any difference.
const RESIDENTIAL = ['search', 'detections', 'alerts', 'cases', 'actions', 'content-packs', 'dashboards', 'notifications', 'threat-intel'];
const ENTERPRISE_ONLY = ['endpoints', 'xdr', 'soar', 'posture', 'compliance', 'ai', 'multi-tenant'];
const BUNDLES = { '@residential': RESIDENTIAL, '@enterprise': [...RESIDENTIAL, ...ENTERPRISE_ONLY] };
const ALL = [...RESIDENTIAL, ...ENTERPRISE_ONLY];
module.exports = { RESIDENTIAL, ENTERPRISE_ONLY, BUNDLES, ALL };
