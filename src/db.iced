
{env} = require './env'
fs = require 'fs'
path = require 'path'
{chain,make_esc} = require 'iced-error'
{mkdirp} = require './fs'
iutils = require 'iced-utils'
{Lock} = iutils.lock
{util} = require 'pgp-utils'
log = require './log'
{constants} = require './constants'
Datastore = require 'nedb'
idb = require 'iced-db'

##=======================================================================

make_key = ({ table, type, id }) -> [ table, type, id].join(":").toLowerCase()
make_kvstore_key = ( {type, key } ) -> 
  type or= key[-2...]
  make_key { table : "kv", type, id : key }
make_lookup_key = ( {type, name} ) -> make_key { table : "lo", type, id : name }

##=======================================================================

class DB

  constructor : ({@filename}) ->
    @lock = new Lock

  #----

  get_filename : () ->
    @filename or= env().get_db_filename()
    return @filename

  #----

  open : (cb) ->
    err = null
    await @_open defer err unless @db?
    cb err

  #----

  unlink : (cb) ->
    fn = @get_filename()
    log.info "Purging local cache: #{fn}"
    await fs.unlink fn, defer err
    cb err

  #----

  close : (cb) ->
    cb null

  #----

  _open : (cb) ->
    esc = make_esc cb, "DB::open"
    err = null
    fn = @get_filename()
    log.debug "+ opening NEDB database file: #{fn}"
    @db = new idb.DB { root : @get_filename(), json : true }
    await @_init_db esc defer()
    log.debug "- DB opened"
    cb null

  #-----

  put : ({type, key, value, name, names}, cb) ->
    kvsk = make_kvstore_key {type,key}
    await @db.put { key : kvsk, value }, defer err, obj
    console.log "put val #{kvsk}"
    unless err?
      {hkey} = obj
      names  = [ name ] if name? and not names?
      if names and names.length
        for name in names
          lk = make_lookup_key(name)
          await @db.put { key : lk, value : hkey }, defer tmp
          console.log "put lookup #{lk} -> #{hkey}"
          if tmp? and not err? then err = tmp
    cb err

  #-----

  remove : ({type, key}, cb) ->
    k = make_kvstore_key { type, key }
    log.debug "+ DB remove #{k}"
    esc = make_esc cb, "DB::remove"

    # XXX error -- we're leaking all of the pointer that pointed to this object.
    # I think it's OK since we're not ever calling remove.
    await @db.del { key : k }, esc defer()

    log.debug "- DB remove #{k} -> ok"
    cb null

  #-----

  find1 : (q, cb) ->
    err = value = null
    await @db.get q, defer err, value
    if err? and (err instanceof idb.E.NotFoundError) then err = null
    else if err? then # noop
    cb err, value

  #-----

  get : ({type, key}, cb) ->
    k = make_kvstore_key { type, key }
    await @find1 { key : k }, defer err, value
    cb err, value

  #-----

  lookup : ({type, name}, cb) ->
    k = make_lookup_key { type, name }
    err = value = null
    await @find1 { key : k }, defer err, value
    if not err? and value?
      await @find1 { hkey : value }, defer err, value
    cb err, value

  #-----

  _init_db : (cb) ->
    log.debug "+ DB::_init_db"
    esc = make_esc cb, "DB::_init_db"
    await @db.create esc defer made
    log.debug "- DB::_init_db -> #{made}"
    cb null

##=======================================================================

exports.db = _db = new DB {}
exports.DB = DB 
for k,v of DB.prototype
  ((key) -> exports[key] = (args...) -> _db[key](args...) )(k)

##=======================================================================
