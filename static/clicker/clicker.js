window.oncontextmenu = (_) => false;

const baseURL = 'https://on-stage.click';
const params = new URLSearchParams(location.search);
const uuid_r = params.get('s');
const prev = document.getElementById('previous');
const next = document.getElementById('next');
const controls = [prev, next];
let checkInterval;

const supports_native_wakelock = typeof navigator.wakeLock !== undefined;
let wakelock = null;

function ensure_wakelock() {
    // native wakelock uses less battery and is prefered, but a 1x1 pixel video can be used if not supported
    if (supports_native_wakelock) {
        if (wakelock != null && !wakelock.released) return;

        console.log('requesting native wakelock');
        navigator.wakeLock.request()
            .then((wl) => {
                console.log('acquired wakelock!');
                wakelock = wl;
            })
            .catch((e) => {
                console.error('failed to acquire wakelock:', e);
            });
    } else {
        // create wakelock video element
        if (wakelock == null) {
            wakelock = document.createElement('video');
            wakelock.setAttribute('playsinline', '');
            wakelock.setAttribute('loop', '');
            wakelock.setAttribute('title', 'Presenting');
            wakelock.setAttribute('src', '/clicker/wakelock.webm');
            document.getElementById('wakelock_fallback').appendChild(wakelock);
        }
        
        // this will fail until the user clicks a button, but nothing can be done about that.
        console.log('falling back to 1x1 pixel video');
        wakelock.play()
            .then(() => {
                console.log('acquired wakelock!');
            })
            .catch((e) => {
                console.error('failed to acquire wakelock:', e);
            });

    }
}

function clear_wakelock() {
    if (wakelock == null) return;

    if (supports_native_wakelock) {
        console.log('releasing native wakelock');
        wakelock.release()
            .then((wl) => {
                console.log('wakelock released!');
                wakelock = null;
            })
            .catch((e) => {
                console.error('failed to release wakelock:', e);
            });
    } else {
        console.log('pausing');
        wakelock.pause();
    }
}

function request(method, path, onLoad) {
    r = new XMLHttpRequest();
    r.onreadystatechange = e => { if (e.target.readyState == 4) onLoad(e) };
    r.open(method, baseURL + path, true);
    r.setRequestHeader('Authorization', uuid_r);
    r.send();
}

const genericHandler = e => {
        let code = e.target.status;
        if (code == 200) {
            // unlock controls
            close_modal();
            ensure_wakelock();  // it would be frustrating if the screen sleeps
        } else if (code == 401) {
            show_blocking_modal(false, 'Session Expired', 'Sorry, this presentation session has expired due to inactivity.');
            clearInterval(checkInterval);   // no use checking
            clear_wakelock();
        } else if (code == 406) {
            // presenting device is offline
            show_blocking_modal(false, 'Computer Offline', 'Could not contact your computer.', true);
        } else if (code > 500 && code != 504) {
            show_blocking_modal(false, 'Temorarily Unavailable', 'Please try again later.', true);
        } else if (code == 0) {
            show_blocking_modal(false, 'Offline', 'Unable to contact server.', true);
        } else {
            console.log(code);
            console.log(e);
            show_blocking_modal(false, 'Temorarily Unavailable', 'Unknown error.', true);
        }
    }

function ping() {
    request('GET', '/api/v1/session/hello', genericHandler);
}

function next_slide() {
    controls.forEach(c => c.disabled = true);
    request('GET', '/api/v1/session/next-slide', genericHandler);
}

function prev_slide() {
    controls.forEach(c => c.disabled = true);
    request('GET', '/api/v1/session/prev-slide', genericHandler);
}


// modal
const body = document.querySelector('body');
const clicker_ui = document.getElementById('clicker_ui');
const modal = {
    modal:   document.getElementById('modal'),
    prompt:  document.getElementById('modal_prompt'),
    title:   document.getElementById('m_title'),
    message: document.getElementById('m_message'),
    ok:      document.getElementById('m_ok'),
    nah:     document.getElementById('m_nah'),
    block:   document.getElementById('modal_block'),
    center_title: document.getElementById('m_center_title'),
    center_msg:   document.getElementById('m_center_msg'),
    wheel:        document.getElementById('m_wheel'),
    reconnect:    document.getElementById('m_reconnect'),
}

function close_modal() {
    modal.modal.classList = ['hidden'];
    body.style.overflow = 'auto';
    clicker_ui.style.animation = 'focus 0.2s ease-out 0ms 1 normal forwards';
}

function show_blocking_modal(loading, title, message=null, show_reconnect=false) {
    modal.prompt.style.display = 'none';
    modal.block.style.display = 'block';
    modal.center_title.innerText = title;

    modal.center_msg.innerText = message;
    modal.center_msg.display = message != null ? 'block' : 'none';
    
    modal.wheel.style.display = loading ? 'block' : 'none';

    if (show_reconnect) {
        modal.reconnect.onclick = (e) => {
            show_blocking_modal(true, 'Reconnecting...');
            ping();
        };
        modal.reconnect.style.display = 'block';
    } else {
        modal.reconnect.style.display = 'none';
    }

    clicker_ui.style.animation = 'defocus 0.2s ease-out 0ms 1 normal forwards';
    modal.modal.classList = ['visible'];
    body.style.overflow = 'hidden';
}

function show_fullscreen_modal() {
    modal.block.style.display = 'none';
    modal.prompt.style.display = 'block';
    modal.title.innerText = 'Fullscreen Mode';
    modal.message.innerText = 'For a better experience, enter fullscreen mode.';
    modal.ok.innerText = 'Enter fullscreen mode';
    modal.nah.innerText = 'No, thanks';

    modal.ok.onclick = (e) => {
        body.requestFullscreen();
        close_modal();
    };

    modal.nah.onclick = (e) => close_modal();

    clicker_ui.style.animation = 'defocus 0.2s ease-out 0ms 1 normal forwards';
    modal.modal.classList = ['visible'];
    body.style.overflow = 'hidden';
}


// show_fullscreen_modal();

if (uuid_r == null) {
    // there is no uuid parameter
    show_blocking_modal(false, 'No Session', 'Please download the extension on your computer and scan the QR code.');
    controls.forEach(c => c.disabled = true);
} else {

    // run when page is loaded, tells presenting device to stop showing the qr code
    show_blocking_modal(true, 'Connecting...');
    ping();

    next.onclick = next_slide;
    prev.onclick = prev_slide;

    // periodically check for availability
    checkInterval = setInterval(ping, 20000);
}