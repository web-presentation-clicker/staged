window.oncontextmenu = (_) => false;

connection = document.getElementById("connection");
connection.innerHTML = "";  // remove noscript tag

const baseURL = 'https://on-stage.click';
const params = new URLSearchParams(location.search);
const uuid_r = params.get('s');
const prev = document.getElementById('previous');
const next = document.getElementById('next');
// const recon = document.getElementById('recon');
const controls = [prev, next];

function request(method, path, onLoad) {
    r = new XMLHttpRequest();
    r.onreadystatechange = e => { if (e.target.readyState == 4) onLoad(e) };
    r.open(method, baseURL + path, true);
    r.setRequestHeader('Authorization', uuid_r);
    r.send();
}

function show(text) {
    connection.textContent = text;
}

const genericHandler = e => {
        let code = e.target.status;
        if (code == 200) {
            // unlock controls
            show('connected');
            controls.forEach(c => c.disabled = false);
        } else if (code == 401) {
            show('sorry, presentation session has expired due to inactivity');
            clearInterval(checkInterval);   // no use checking
            controls.forEach(c => c.disabled = true);
        } else if (code == 406) {
            // presenting device is offline
            show('presenting device is not connected');
            controls.forEach(c => c.disabled = true);
            // todo: show retry button
        } else if (code > 500 && code != 504) {
            show('service unavailable, please try again later');
            controls.forEach(c => c.disabled = true);
            // todo: show retry button
        } else if (code == 0) {
            show('unable to contact server');
            controls.forEach(c => c.disabled = true);
            // todo: show retry button
        } else {
            console.log(code);
            console.log(e);
            show('unknown error');
            // todo: show retry button
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
    title:   document.getElementById('m_title'),
    message: document.getElementById('m_message'),
    ok:      document.getElementById('m_ok'),
    nah:     document.getElementById('m_nah'),
}

function close_modal() {
    modal.modal.classList = ['hidden'];
    body.style.overflow = 'auto';
    clicker_ui.style.animation = 'focus 0.2s ease-out 0ms 1 normal forwards';

}

function show_fullscreen_modal() {

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


show_fullscreen_modal();

if (uuid_r == null) {
    // there is no uuid parameter
    connection.textContent = "no session: Please download the extension on your computer and scan the QR code.";
    controls.forEach(c => c.disabled = true);
} else {

    // run when page is loaded, tells presenting device to stop showing the qr code
    connection.textContent = "connecting...";
    ping();

    next.onclick = next_slide;
    prev.onclick = prev_slide;

    // periodically check for availability
    let checkInterval = setInterval(ping, 20000);
}