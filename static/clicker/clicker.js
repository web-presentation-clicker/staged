window.oncontextmenu = (_) => false;

const baseURL = '';
const params = new URLSearchParams(location.search);
const uuid_r = params.get('s');
const prev = document.getElementById('previous');
const next = document.getElementById('next');
const fullscreen = document.getElementById('fullscreen_button');
const controls = [prev, next];
let checkInterval;
let blocking = false;

const supports_native_wakelock = typeof navigator.wakeLock !== 'undefined';
let wakelock = null;

const is_playing = (vid) => !vid.paused && !vid.ended && vid.readyState > 2 && vid.currentTime > 0.0;

function add_video_source(video, src, type) {
    let source = document.createElement('source');
    source.src = src;
    source.type = type;
    video.appendChild(source);
}

function create_wakelock_fallback() {
    wakelock = document.createElement('video');
    // looping the video on iOS 15 makes it not work
    wakelock.setAttribute('playsinline', '');
    wakelock.setAttribute('title', 'Presenting');

    // Note: Safari apparently doesn't support vp9 anymore for some reason. Why???
    add_video_source(wakelock, '/clicker/wakelock.webm', 'video/webm; codecs="vp9,opus"');

    // the iPhone I test with doesn't support webm containers at all
    add_video_source(wakelock, '/clicker/wakelock.mp4', 'video/mp4; codecs="avc1.4d002a,mp4a.40.2"');

    document.getElementById('wakelock_fallback').appendChild(wakelock);

    // loop manually since the loop tag breaks it
    wakelock.ontimeupdate = () => { if (wakelock.currentTime > 2.0) wakelock.currentTime = 0.69; }
}

function ensure_wakelock() {
    let wl_promise;

    // native wakelock uses less battery and is prefered, but a 1x1 pixel video can be used if not supported
    if (supports_native_wakelock) {
        if (wakelock != null && !wakelock.released) return;

        console.log('requesting native wakelock');
        wl_promise = navigator.wakeLock.request()
            .then((wl) => wakelock = wl);

    } else {
        // create wakelock video element
        if (wakelock == null) create_wakelock_fallback();
        else if (is_playing(wakelock)) return;

        console.log('falling back to *small* video');  
        // this will fail until the user clicks a button, but nothing can be done about that.
        wl_promise = wakelock.play();
    }

    wl_promise
        .then(() => console.log('acquired wakelock!'))
        .catch((e) => console.error('failed to acquire wakelock:', e));
}

function clear_wakelock() {
    if (wakelock == null) return;

    if (supports_native_wakelock) {
        console.log('releasing native wakelock');
        wakelock.release()
            .then(() => {
                console.log('wakelock released!');
                wakelock = null;
            })
            .catch((e) => console.error('failed to release wakelock:', e));
    } else {
        console.log('pausing wakelock fallback video');
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
            if (blocking) close_modal();
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
    };

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

let modal_open = false;

// helpers
const hide = (e) => e.style.display = 'none';
const unhide = (e) => e.style.display = '';
const set_hidden = (e, d) => (d ? hide : unhide)(e);

// reconnect always reconnects
modal.reconnect.onclick = (e) => {
    show_blocking_modal(true, 'Reconnecting...');
    ping();
};

function close_modal() {
    if (!modal_open) return false;
    modal_open = false;
    blocking = false;
    
    modal.modal.classList = ['hidden'];
    clicker_ui.style.animation = 'focus 0.2s ease-in';
    // interesting firefox (race condition?) mitigation
    setTimeout(() => hide(modal.modal), 200);
}

function open_modal(focus_item) {
    modal_open = true;

    unhide(modal.modal);
    clicker_ui.style.animation = 'defocus 0.2s ease-out 0ms 1 normal forwards';
    modal.modal.classList = ['visible'];
}

function show_blocking_modal(loading, title, message=null, show_reconnect=false) {
    hide(modal.prompt);
    unhide(modal.block);

    modal.center_title.innerText = title;
    modal.center_msg.innerText = message;

    set_hidden(modal.center_msg, message == null);
    set_hidden(modal.wheel, !loading);
    set_hidden(modal.reconnect, !show_reconnect);

    blocking = true;
    open_modal();
}

function show_fullscreen_modal() {
    hide(modal.block);
    unhide(modal.prompt);
    
    modal.title.innerText = 'Fullscreen Mode';
    modal.message.innerText = 'For a better experience, enter fullscreen mode.';
    modal.ok.innerText = 'Enter fullscreen mode';
    modal.nah.innerText = 'No, thanks';

    modal.ok.onclick = (e) => {
        body.requestFullscreen({navigationUI: 'hide'});
        close_modal();
    };

    modal.nah.onclick = (e) => close_modal();

    open_modal();
}

function on_fullscreen_state(is_fs) {
    if (is_fs) {
        fullscreen.onclick = () => document.exitFullscreen();
        fullscreen.style.backgroundImage = 'url("/img/exit-fullscreen.svg")';
    } else {
        fullscreen.onclick = show_fullscreen_modal;
        fullscreen.style.backgroundImage = '';
    }
}

// set up fullscreen
if (document.fullscreenEnabled) {
    document.onfullscreenchange = () => on_fullscreen_state(document.fullscreenElement != null);
    document.onfullscreenchange();  // set up button
} else {
    // Apple can't decide if they want fullscreen
    hide(fullscreen);
}


if (uuid_r == null) {
    // there is no uuid parameter
    show_blocking_modal(false, 'No Session', 'Please download the extension on your computer and scan the QR code.');
    controls.forEach(c => c.disabled = true);
} else {

    // run when page is loaded, tells presenting device to stop showing the qr code
    show_blocking_modal(true, 'Connecting...');
    ping();

    next.onmousedown = next_slide;
    prev.onmousedown = prev_slide;

    // periodically check for availability
    checkInterval = setInterval(ping, 20000);
}