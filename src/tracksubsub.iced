
{db} = require './db'
{constants} = require './constants'
log = require './log'
proofs = require 'keybase-proofs'
{proof_type_to_string} = proofs
ST = constants.signature_types
deq = require 'deep-equal'
{E} = require './err'
{unix_time} = require('pgp-utils').util
{make_esc} = require 'iced-error'
{prompt_yn} = require './prompter'
colors = require 'colors'
{session} = require './session'
{User} = require './user'
db = require './db'
util = require 'util'
{env} = require './env'
{TrackWrapper} = require './trackwrapper'
{TmpKeyRing} = require './keyring'

##=======================================================================

exports.TrackSubSubCommand = class TrackSubSubCommand

  #----------------------

  constructor : ({@args, @opts}) ->

  #----------------------

  prompt_ok : (warnings, cb) ->
    prompt = if warnings
      log.console.log colors.red "Some remote proofs failed!"
      "Still verify this user?"
    else
      "Are you satisfied with these proofs?"
    await prompt_yn { prompt, defval : false }, defer err, ret
    cb err, ret

  #----------

  prompt_track : (cb) ->
    ret = err = null
    if @opts.remote then ret = true
    else if (@opts.batch or @opts.local) then ret = false
    else
      prompt = "Permnanently track this user, and write proof to server?"
      await prompt_yn { prompt, defval : true }, defer err, ret
    cb err, ret

  #----------

  _key_cleanup : ({accept}, cb) ->
    err = null
    if accept 
      log.debug "| commit_key"
      await @them.key.commit @me?.key, defer err
    else
      await @them.key.rollback defer err
      
    if not @tmp_keyring then #noop
    else if env().get_preserve_tmp_keyring()
      log.info "Preserving #{@tmp_keyring.to_string()}"
    else
      await @tmp_keyring.nuke defer e2
      log.warn "Problem in cleanup: #{e2.message}" if e2?
    cb err

  #----------

  id : (cb) ->
    esc = make_esc cb, "TrackSubSub:id"
    log.debug "+ id"
    accept = false
    await User.load { username : @args.them }, esc defer @them
    await TmpKeyRing.make esc defer @tmp_keyring
    await @_id2 { @them }, esc defer()
    await @_key_cleanup { }, esc defer()
    log.debug "- id"
    cb null

  #----------

  _id2 : ({them}, cb ) ->
    esc = make_esc cb, "TrackSubSub:_id2"
    log.debug "+ _id2"
    await them.import_public_key { keyring : @tmp_keyring }, esc defer()
    await them.verify esc defer()
    await them.check_remote_proofs false, esc defer warnings # err isn't a failure here
    log.debug "- _id2"
    cb null

  #----------

  run : (cb) ->
    esc = make_esc cb, "TrackSubSub::run"
    log.debug "+ run"

    await User.load_me esc defer @me
    await User.load { username : @args.them }, esc defer @them
    await @me.new_tmp_keyring { secret : true }, esc defer @tmp_keyring

    # After this point, we have to recover any errors and throw away 
    # our key if necessary. So call into a subfunction.
    await @_run2 defer err, accept

    # Clean up the key if necessary
    await @_key_cleanup { accept }, esc defer()

    log.debug "- run"

    cb err

  #----------

  _run2 : (cb) ->
    esc = make_esc cb, "TrackSubSub::_run2"
    log.debug "+ _run2"

    await @them.import_public_key { keyring: @tmp_keyring }, esc defer()
    await @them.verify esc defer()
    await TrackWrapper.load { tracker : @me, trackee : @them }, esc defer trackw
    
    check = trackw.skip_remote_check()
    if (check is constants.skip.NONE)
      log.console.log "...checking identity proofs"
      skp = false
    else 
      log.info "...all remote checks are up-to-date"
      skp = true
    await @them.check_remote_proofs skp, esc defer warnings
    n_warnings = warnings.warnings().length

    if ((approve = trackw.skip_approval()) isnt constants.skip.NONE)
      log.debug "| skipping approval, since remote services & key are unchanged"
      accept = true
    else if @opts.batch
      log.debug "| We needed approval, but we were in batch mode"
      accept = false
    else
      await @prompt_ok n_warnings, esc defer accept

    err = null
    if not accept
      log.warn "Bailing out; proofs were not accepted"
      err = new E.CancelError "operation was canceled"
    else if (check is constants.skip.REMOTE) and (approve is constants.skip.REMOTE)
      log.info "Nothing to do; tracking is up-to-date"
    else
      await @prompt_track esc defer do_remote
      await session.load_and_login esc defer() if do_remote
      await trackw.store_track { do_remote }, esc defer()

    log.debug "- _run2"
    cb err, accept 

##=======================================================================