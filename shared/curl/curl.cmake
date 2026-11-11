# curl, pinned once for both consoles' apps (each console's dependencies.cmake includes this): the
# Mozilla CA bundle download and the new-release check. To update it, change the version and SHA-256
# together; the SHA-256 is that of the release archive below (`sha256sum curl-8.17.0.tar.gz`)
set(VITALS_CURL_VERSION "8.17.0")
set(VITALS_CURL_SHA256 "e8e74cdeefe5fb78b3ae6e90cd542babf788fa9480029cfcee6fd9ced42b7910")
set(VITALS_CURL_URL "https://curl.se/download/curl-${VITALS_CURL_VERSION}.tar.gz")
