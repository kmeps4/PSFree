fetch('./payload.bin').then(res => {
    res.arrayBuffer().then(arr => {
        window.pld = new Uint32Array(arr);

    })
})