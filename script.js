function decodeHexB64(el) {
    var h1 = document.getElementById('hex1');
    var h2 = document.getElementById('hex2');
    var h3 = document.getElementById('hex3');

    var raw1 = h1.textContent.trim();
    var raw2 = h2.textContent.trim();
    var raw3 = h3.textContent.trim();
    var allHex = raw1 + ' ' + raw2 + ' ' + raw3;

    var parts = allHex.split(' ');
    var b64 = parts.map(function(h) { return String.fromCharCode(parseInt(h, 16)); }).join('');
    var answer = atob(b64);

    var box = document.createElement('div');
    box.style.marginTop = '16px';
    box.style.border = '1px solid var(--gray)';
    box.style.padding = '12px';
    box.style.fontSize = '16px';
    box.style.lineHeight = '2';
    box.style.fontFamily = "'Courier New', Courier, monospace";

    h3.parentNode.insertBefore(box, h3.nextSibling);

    var lines = [];

    var l1 = document.createElement('div');
    l1.style.color = 'var(--gray)';
    l1.textContent = '$ echo "' + allHex + '" | tr -d \'0x\' | xxd -r -p';
    lines.push(l1);

    var l2 = document.createElement('div');
    l2.style.color = 'var(--lime)';
    l2.textContent = '> ' + b64;
    lines.push(l2);

    var l3 = document.createElement('div');
    l3.style.color = 'var(--gray)';
    l3.textContent = '$ base64 -d ' + b64;
    lines.push(l3);

    var l4 = document.createElement('div');
    l4.style.color = 'var(--lime)';
    l4.textContent = '> ' + answer;
    lines.push(l4);

    box.appendChild(lines[0]);
    setTimeout(function() {
        box.appendChild(lines[1]);
        box.appendChild(lines[2]);
        setTimeout(function() {
            box.appendChild(lines[3]);
        }, 1000);
    }, 1000);

    h1.onclick = null;
    h2.onclick = null;
    h3.onclick = null;
    h1.style.cursor = 'default';
    h2.style.cursor = 'default';
    h3.style.cursor = 'default';
}

