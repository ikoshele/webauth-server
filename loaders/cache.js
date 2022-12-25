import NodeCache from 'node-cache'
const cache = new NodeCache( { stdTTL: 3600, checkperiod: 6200 } );
cache.on( "expired", function( key, value ){
    cache.del(key);
});
export default cache;