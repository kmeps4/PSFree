if (sessionStorage.getItem('jbsuccess')) {
    sessionStorage.setItem('binloader', 1);
} else {
    fetch('./payload.bin').then(res => {
        res.arrayBuffer().then(arr => {
            window.pld = new Uint32Array(arr);
            sessionStorage.setItem('jbsuccess', 1);
        })
    })
}
