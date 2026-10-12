-- Applied after browser-session migration by the ordinary migration owner.
REVOKE ALL ON browser_login_challenges,browser_session_routes,browser_sessions FROM sandbox_app;
GRANT EXECUTE ON FUNCTION
 sandbox_browser_login_create(uuid,uuid,uuid,text,text,bytea),
 sandbox_browser_login_consume(text,text),
 sandbox_browser_session_create(uuid,uuid,text,text,text,text,timestamptz,bytea,uuid),
 sandbox_browser_session_read(text,boolean),
 sandbox_browser_refresh_begin(text,bigint),
 sandbox_browser_refresh_finish(text,bigint,timestamptz,bytea),
 sandbox_browser_session_revoke(text,text,bigint,uuid),
 sandbox_browser_cleanup(uuid)
TO sandbox_app;
