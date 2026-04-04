import os
import sys
import archinfo
import random
import angr
import claripy as cl

k0 = cl.BVS("k0", 32)
k1 = cl.BVS("k1", 32)
k2 = cl.BVS("k2", 32)
k3 = cl.BVS("k3", 32)
r0 = cl.BVS("r0", 32)
r1 = cl.BVS("r1", 32)
r2 = cl.BVS("r2", 32)
r3 = cl.BVS("r3", 32)
n0 = cl.BVS("n0", 32)
n1 = cl.BVS("n1", 32)
n2 = cl.BVS("n2", 32)

i0 = cl.BVS("i0", 32)
i1 = cl.BVS("i1", 32)
i2 = cl.BVS("i2", 32)
i3 = cl.BVS("i3", 32)


# Stub function to return zero
class ReturnZero(angr.SimProcedure):
    def run(self, *args, **kwargs):
        return cl.BVV(0, self.state.arch.bits)


# Salt for Argon2id
class generateSalt(angr.SimProcedure):
    def run(self, salt_ptr, salt_size):
        for i in range(len(salt_size)):
            #s = cl.BVS(f"salt{i}", 8)
            s = cl.BVV(i, 8)
            self.state.memory.store(salt_ptr + i, s)
            print(self.state.memory.load(salt_ptr + i, 1))
        return


# Nonce for Poly1305
class generateNonce(angr.SimProcedure):
    def run(self, nonce, n=None):
        print(self.state)
        print(f"nonce pointer: {nonce}")

        # Reversed for endianness
        if n is None:
            self.state.memory.store(nonce, n0.reversed)
            self.state.memory.store(nonce+4, n1.reversed)
            self.state.memory.store(nonce+8, n2.reversed)
        else:
            self.state.memory.store(nonce, cl.BVV(n[0], 32))
            self.state.memory.store(nonce+4, cl.BVV(n[1], 32))
            self.state.memory.store(nonce+8, cl.BVV(n[2], 32))

        print(self.state.memory.load(nonce, 4))
        print(self.state.memory.load(nonce+4, 4))
        print(self.state.memory.load(nonce+8, 4))
        return


# Key for Poly1305
class generateKey(angr.SimProcedure):
    def run(self, privk, k=None):
        print(self.state)
        print(f"private key pointer: {privk}")

        # Reversed for endianness
        if k is None:
            self.state.memory.store(privk, k0.reversed)
            self.state.memory.store(privk+4, k1.reversed)
            self.state.memory.store(privk+8, k2.reversed)
            self.state.memory.store(privk+12, k3.reversed)
            self.state.memory.store(privk+16, r0.reversed)
            self.state.memory.store(privk+20, r1.reversed)
            self.state.memory.store(privk+24, r2.reversed)
            self.state.memory.store(privk+28, r3.reversed)

        else:
            self.state.memory.store(privk, cl.BVV(k[0], 32))
            self.state.memory.store(privk+4, cl.BVV(k[1], 32))
            self.state.memory.store(privk+8, cl.BVV(k[2], 32))
            self.state.memory.store(privk+12, cl.BVV(k[3], 32))
            self.state.memory.store(privk+16, cl.BVV(k[4], 32))
            self.state.memory.store(privk+20, cl.BVV(k[5], 32))
            self.state.memory.store(privk+24, cl.BVV(k[6], 32))
            self.state.memory.store(privk+28, cl.BVV(k[7], 32))

        print(self.state.memory.load(privk, 4))
        print(self.state.memory.load(privk+4, 4))
        print(self.state.memory.load(privk+8, 4))
        print(self.state.memory.load(privk+12,4))

        print(self.state.memory.load(privk+16, 4))
        print(self.state.memory.load(privk+20, 4))
        print(self.state.memory.load(privk+24, 4))
        print(self.state.memory.load(privk+28, 4))
        return


# randombytes_buf
class randombytes_buf(angr.SimProcedure):
    def run(self, seed, length):
        print(self.state)
        z = cl.BVV(0, 8)
        for i in range(32):
            self.state.memory.store(seed+i, z)
        return


# Private keys for ED25519
class generatePrivKeyEd25519(angr.SimProcedure):
    def run(self, sk, seed, length, k1=None):
        print(self.state)
        privk = sk
        print(f"private key pointer: {privk}")

        # Reversed for endianness
        size = 8
        mem_idx = int(size/8)
        if k1 is None:
            for i in range(int(256/size)):
                symb = cl.BVS(f"privk_{i}", size)
                self.state.memory.store(privk + i*mem_idx, symb.reversed)
        else:
            self.state.memory.store(privk, cl.BVV(k1[0], 32))
            self.state.memory.store(privk+4, cl.BVV(k1[1], 32))
            self.state.memory.store(privk+8, cl.BVV(k1[2], 32))
            self.state.memory.store(privk+12, cl.BVV(k1[3], 32))
            self.state.memory.store(privk+16, cl.BVV(k1[4], 32))
            self.state.memory.store(privk+20, cl.BVV(k1[5], 32))
            self.state.memory.store(privk+24, cl.BVV(k1[6], 32))
            self.state.memory.store(privk+28, cl.BVV(k1[7], 32))

        print(self.state.memory.load(privk, 32))
        print(self.state.memory.load(seed, 32))

        return

# Public and private keys for ED25519
class generateKeyEd25519(angr.SimProcedure):
    def run(self, pubk, privk, k1=None, k2=None):
        print(self.state)
        print(f"private key pointer: {privk}")
        print(f"public key pointer: {pubk}")

        privk0 = cl.BVS("k0", 32)
        privk1 = cl.BVS("k1", 32)
        privk2 = cl.BVS("k2", 32)
        privk3 = cl.BVS("k3", 32)
        privk4 = cl.BVS("k4", 32)
        privk5 = cl.BVS("k5", 32)
        privk6 = cl.BVS("k6", 32)
        privk7 = cl.BVS("k7", 32)

        pubk0 = cl.BVS("pubk0", 32)
        pubk1 = cl.BVS("pubk1", 32)
        pubk2 = cl.BVS("pubk2", 32)
        pubk3 = cl.BVS("pubk3", 32)
        pubk4 = cl.BVS("pubk4", 32)
        pubk5 = cl.BVS("pubk5", 32)
        pubk6 = cl.BVS("pubk6", 32)
        pubk7 = cl.BVS("pubk7", 32)

        # Reversed for endianness
        if k1 is None:
            self.state.memory.store(privk, privk0.reversed)
            self.state.memory.store(privk+4, privk1.reversed)
            self.state.memory.store(privk+8, privk2.reversed)
            self.state.memory.store(privk+12, privk3.reversed)
            self.state.memory.store(privk+16, privk4.reversed)
            self.state.memory.store(privk+20, privk5.reversed)
            self.state.memory.store(privk+24, privk6.reversed)
            self.state.memory.store(privk+28, privk7.reversed)

        else:
            self.state.memory.store(privk, cl.BVV(k1[0], 32))
            self.state.memory.store(privk+4, cl.BVV(k1[1], 32))
            self.state.memory.store(privk+8, cl.BVV(k1[2], 32))
            self.state.memory.store(privk+12, cl.BVV(k1[3], 32))
            self.state.memory.store(privk+16, cl.BVV(k1[4], 32))
            self.state.memory.store(privk+20, cl.BVV(k1[5], 32))
            self.state.memory.store(privk+24, cl.BVV(k1[6], 32))
            self.state.memory.store(privk+28, cl.BVV(k1[7], 32))

        if k2 is None:
            self.state.memory.store(pubk, pubk0.reversed)
            self.state.memory.store(pubk+4, pubk1.reversed)
            self.state.memory.store(pubk+8, pubk2.reversed)
            self.state.memory.store(pubk+12, pubk3.reversed)


            privk_2 = privk + 32
            self.state.memory.store(privk_2, pubk0.reversed)
            self.state.memory.store(privk_2+4, pubk1.reversed)
            self.state.memory.store(privk_2+8, pubk2.reversed)
            self.state.memory.store(privk_2+12, pubk3.reversed)
            self.state.memory.store(privk_2+16, pubk4.reversed)
            self.state.memory.store(privk_2+20, pubk5.reversed)
            self.state.memory.store(privk_2+24, pubk6.reversed)
            self.state.memory.store(privk_2+28, pubk7.reversed)

        else:
            self.state.memory.store(pubk, cl.BVV(k2[0], 32))
            self.state.memory.store(pubk+4, cl.BVV(k2[1], 32))
            self.state.memory.store(pubk+8, cl.BVV(k2[2], 32))
            self.state.memory.store(pubk+12, cl.BVV(k2[3], 32))
            self.state.memory.store(pubk+16, cl.BVV(k2[4], 32))
            self.state.memory.store(pubk+20, cl.BVV(k2[5], 32))
            self.state.memory.store(pubk+24, cl.BVV(k2[6], 32))
            self.state.memory.store(pubk+28, cl.BVV(k2[7], 32))
        
            privk_2 = privk + 32
            self.state.memory.store(privk_2, cl.BVV(k2[0], 32))
            self.state.memory.store(privk_2+4, cl.BVV(k2[1], 32))
            self.state.memory.store(privk_2+8, cl.BVV(k2[2], 32))
            self.state.memory.store(privk_2+12, cl.BVV(k2[3], 32))
            self.state.memory.store(privk_2+16, cl.BVV(k2[4], 32))
            self.state.memory.store(privk_2+20, cl.BVV(k2[5], 32))
            self.state.memory.store(privk_2+24, cl.BVV(k2[6], 32))
            self.state.memory.store(privk_2+28, cl.BVV(k2[7], 32))

        print(self.state.memory.load(privk, 4))
        print(self.state.memory.load(privk+4, 4))
        print(self.state.memory.load(privk+8, 4))
        print(self.state.memory.load(privk+12,4))

        print(self.state.memory.load(privk+16, 4))
        print(self.state.memory.load(privk+20, 4))
        print(self.state.memory.load(privk+24, 4))
        print(self.state.memory.load(privk+28, 4))

        print(self.state.memory.load(pubk, 4))
        print(self.state.memory.load(pubk+4, 4))
        print(self.state.memory.load(pubk+8, 4))
        print(self.state.memory.load(pubk+12,4))
        return


def chacha20_init(proj, simulate=False):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    arg_str = "1 0 11AJfA0kjnfskjf 0 file file2"
    #arg_str = "16 234 234 234 23 2 5 22 23 2323 23 23 4 2 15 543 4"
    arg_str_split = arg_str.split()
    for a in arg_str_split:
        argv.append(a)
    print(f"args: {argv}")

    # These concretize values for chacha20
    k=list()
    n=list()
    for i in range(8):
        k.append(random.getrandbits(32))
    for i in range(3):
        n.append(random.getrandbits(32))
    proj.hook_symbol('crypto_aead_chacha20poly1305_ietf_keygen', generateKey(k=k))
    proj.hook_symbol('ciocc_eval_rand_fill_buf', generateNonce(n=n))
    return proj, argv


def helium_eval_poly1305(proj, simulate=False):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    arg_str = "hello world"
    arg_str_split = arg_str.split()
    for a in arg_str_split:
        argv.append(a)
    print(f"args: {argv}")

    # These concretize values for chacha20
    k=[1,2,3,4,5,6,7,8]
    n=[10,11,12]
    proj.hook_symbol('crypto_aead_chacha20poly1305_ietf_keygen', generateKey(k=k))
    proj.hook_symbol('ciocc_eval_rand_fill_buf', generateNonce(n=n))

    # Set the key and message symbolic before poly1305 only
    poly1305_init_addr = proj.loader.main_object.get_symbol("crypto_onetimeauth_poly1305_donna_init")

    @proj.hook(poly1305_init_addr.rebased_addr)
    def setKeySymb(state):
        print(state)
        if simulate:
            r0 = 10
            r1 = 11
            r2 = 12
            r3 = 14
            k0 = 15
            k1 = 16
            k2 = 17
            k3 = 18
        else:
            k0 = cl.BVS("k0", 32)
            k1 = cl.BVS("k1", 32)
            k2 = cl.BVS("k2", 32)
            k3 = cl.BVS("k3", 32)
            r0 = cl.BVS("r0", 32)
            r1 = cl.BVS("r1", 32)
            r2 = cl.BVS("r2", 32)
            r3 = cl.BVS("r3", 32)
        privk = state.regs.rsi
        # Reversed for endianness
        state.memory.store(privk, r0, endness=archinfo.Endness.LE)
        state.memory.store(privk+4, r1, endness=archinfo.Endness.LE)
        state.memory.store(privk+8, r2, endness=archinfo.Endness.LE)
        state.memory.store(privk+12, r3, endness=archinfo.Endness.LE)

        state.memory.store(privk+16, k0, endness=archinfo.Endness.LE)
        state.memory.store(privk+20, k1, endness=archinfo.Endness.LE)
        state.memory.store(privk+24, k2, endness=archinfo.Endness.LE)
        state.memory.store(privk+28, k3, endness=archinfo.Endness.LE)

        print(state.memory.load(privk, 4))
        print(state.memory.load(privk+4, 4))
        print(state.memory.load(privk+8, 4))
        print(state.memory.load(privk+12,4))

        print(state.memory.load(privk+16, 4))
        print(state.memory.load(privk+20, 4))
        print(state.memory.load(privk+24, 4))
        print(state.memory.load(privk+28, 4))
        print(f"key pointer: {privk}")

    poly1305_blocks_addr = proj.loader.main_object.get_symbol("poly1305_blocks")

    @proj.hook(poly1305_blocks_addr.rebased_addr)
    def setInpSymb(state):
        print(state)
        inp = state.regs.rsi

        if simulate:
            #i0 = random.getrandbits(32)
            #i1 = random.getrandbits(32)
            #i2 = random.getrandbits(32)
            #i3 = random.getrandbits(32)
            i0 = 1
            i1 = 2
            i2 = 3
            i3 = 4
        else:
            i0 = cl.BVS("i0", 32)
            i1 = cl.BVS("i1", 32)
            i2 = cl.BVS("i2", 32)
            i3 = cl.BVS("i3", 32)

        # Reversed for endianness
        state.memory.store(inp, i0, endness=archinfo.Endness.LE)
        state.memory.store(inp+4, i1, endness=archinfo.Endness.LE)
        state.memory.store(inp+8, i2, endness=archinfo.Endness.LE)
        state.memory.store(inp+12, i3, endness=archinfo.Endness.LE)

        print(state.memory.load(inp, 4))
        print(state.memory.load(inp+4, 4))
        print(state.memory.load(inp+8, 4))
        print(state.memory.load(inp+12,4))
        print(f"message pointer: {inp}")

    return proj, argv


def poly1305_init(proj, simulate=False):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    arg_str = "1 0 helloworld 0 file file2"
    #arg_str = "16 234 234 234 23 2 5 22 23 2323 23 23 4 2 15 543 4"
    arg_str_split = arg_str.split()
    for a in arg_str_split:
        argv.append(a)
    print(f"args: {argv}")

    # These concretize values for chacha20
    k=[1,2,3,4,5,6,7,8]
    n=[10,11,12]
    proj.hook_symbol('crypto_aead_chacha20poly1305_ietf_keygen', generateKey(k=k))
    proj.hook_symbol('ciocc_eval_rand_fill_buf', generateNonce(n=n))

    # Set the key and message symbolic before poly1305 only
    poly1305_init_addr = proj.loader.main_object.get_symbol("crypto_onetimeauth_poly1305_donna_init")
    
    @proj.hook(poly1305_init_addr.rebased_addr)
    def setKeySymb(state):
        print(state)
   
        if simulate:
            #r0 = random.getrandbits(32)
            #r1 = random.getrandbits(32)
            #r2 = random.getrandbits(32)
            #r3 = random.getrandbits(32)
            #k0 = random.getrandbits(32)
            #k1 = random.getrandbits(32)
            #k2 = random.getrandbits(32)
            #k3 = random.getrandbits(32)
            r0 = 10
            r1 = 11
            r2 = 12
            r3 = 14
            k0 = 15
            k1 = 16
            k2 = 17
            k3 = 18
        else:
            k0 = cl.BVS("k0", 32)
            k1 = cl.BVS("k1", 32)
            k2 = cl.BVS("k2", 32)
            k3 = cl.BVS("k3", 32)
            r0 = cl.BVS("r0", 32)
            r1 = cl.BVS("r1", 32)
            r2 = cl.BVS("r2", 32)
            r3 = cl.BVS("r3", 32)
        privk = state.regs.rsi
    
        # Reversed for endianness
        state.memory.store(privk, r0, endness=archinfo.Endness.LE)
        state.memory.store(privk+4, r1, endness=archinfo.Endness.LE)
        state.memory.store(privk+8, r2, endness=archinfo.Endness.LE)
        state.memory.store(privk+12, r3, endness=archinfo.Endness.LE)
    
        state.memory.store(privk+16, k0, endness=archinfo.Endness.LE)
        state.memory.store(privk+20, k1, endness=archinfo.Endness.LE)
        state.memory.store(privk+24, k2, endness=archinfo.Endness.LE)
        state.memory.store(privk+28, k3, endness=archinfo.Endness.LE)
    
        print(state.memory.load(privk, 4))
        print(state.memory.load(privk+4, 4))
        print(state.memory.load(privk+8, 4))
        print(state.memory.load(privk+12,4))
    
        print(state.memory.load(privk+16, 4))
        print(state.memory.load(privk+20, 4))
        print(state.memory.load(privk+24, 4))
        print(state.memory.load(privk+28, 4))
        print(f"key pointer: {privk}")

    poly1305_blocks_addr = proj.loader.main_object.get_symbol("poly1305_blocks")
    
    @proj.hook(poly1305_blocks_addr.rebased_addr)
    def setInpSymb(state):
        print(state)
        inp = state.regs.rsi
   
        if simulate:
            #i0 = random.getrandbits(32)
            #i1 = random.getrandbits(32)
            #i2 = random.getrandbits(32)
            #i3 = random.getrandbits(32)
            i0 = 1
            i1 = 2
            i2 = 3
            i3 = 4
        else:
            i0 = cl.BVS("i0", 32)
            i1 = cl.BVS("i1", 32)
            i2 = cl.BVS("i2", 32)
            i3 = cl.BVS("i3", 32)

        # Reversed for endianness
        state.memory.store(inp, i0, endness=archinfo.Endness.LE)
        state.memory.store(inp+4, i1, endness=archinfo.Endness.LE)
        state.memory.store(inp+8, i2, endness=archinfo.Endness.LE)
        state.memory.store(inp+12, i3, endness=archinfo.Endness.LE)
    
        print(state.memory.load(inp, 4))
        print(state.memory.load(inp+4, 4))
        print(state.memory.load(inp+8, 4))
        print(state.memory.load(inp+12,4))
        print(f"message pointer: {inp}")
    
    return proj, argv 


def ed25519_init(proj):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    arg_str = "1 0 11AJfA0tOFxsdjfnskjnfskjf 0 file file2"
    #arg_str = "16 234 234 234 23 2 5 22 23 2323 23 23 4 2 15 543 4"
    arg_str_split = arg_str.split()
    for a in arg_str_split:
        argv.append(a)
    print(f"args: {argv}")

    k1=[1,2,3,4,5,6,7,8]
    k2=[9,10,11,12,13,14,15,16]
    k1 = None
    k2 = None
    proj.hook_symbol('crypto_sign_keypair', generateKeyEd25519(k1=k1, k2=k2))
    return proj, argv


# Generation of public key from private key
def ed25519_keygen_init(proj):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    arg_str = "1 0 11AJfA0tOjnfskjf 0 file file2"
    arg_str_split = arg_str.split()
    for a in arg_str_split:
        argv.append(a)
    print(f"args: {argv}")

    #
    proj.hook_symbol('randombytes_buf', randombytes_buf())

    #k1 = [0,0,0,0,0,0,0,0]
    k1 = None
    proj.hook_symbol('crypto_hash_sha512', generatePrivKeyEd25519(k1=k1))

    # Set private key symbolic before generating public key
    #ge25519_scalarmult_base_addr = 0x411450
    #
    #@proj.hook(ge25519_scalarmult_base_addr)
    #def setSymb(state):
    #    privkey_ptr = state.regs.rsi
    #    print(f"addr of privkey: {privkey_ptr}")
    #    for i in range(32):
    #        print(f"i {i}")
    #        sym_hex = cl.BVS(f"sym_hex{i}", 8)
    #        state.memory.store(privkey_ptr + i, sym_hex)
    #
    #    print(f"Stored values: {state.memory.load(addr, 32)}") 

    return proj, argv


def argon2id_init(proj):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    arg_str = "1 0 11AJfA0tOFxsdjfnskjnfskjf 0 file file2"
    #arg_str = "16 234 234 234 23 2 5 22 23 2323 23 23 4 2 15 543 4"
    arg_str_split = arg_str.split()
    for a in arg_str_split:
        argv.append(a)
    print(f"args: {argv}")

    args = ()
    proj.hook_symbol('randombytes_buf', generateSalt())
    return proj, argv


def simple_init(proj):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    arg_str = "1 0 11AJfA0tOFxsdjfnskjnfskjf 0 file file2"
    #arg_str = "16 234 234 234 23 2 5 22 23 2323 23 23 4 2 15 543 4"
    arg_str_split = arg_str.split()
    for a in arg_str_split:
        argv.append(a)
    print(f"args: {argv}")

    @proj.hook(0x401163)
    def setSymb(state):
        print(state)
        a = cl.BVS("a", 32)
        b = cl.BVS("b", 32)
        state.memory.store(state.regs.rbp - 8, b.reversed )
        state.memory.store(state.regs.rbp - 0xc, a.reversed )
        print(state.memory.load(state.regs.rbp - 8, 4))
        print(state.memory.load(state.regs.rbp - 0xc, 4))

    return proj, argv


def sha512_init(proj):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    argv.append("0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a000000017fffffde00")
    print(f"args: {argv}")

    @proj.hook(0x402b80)
    def setInput(state):
        print("inside hook")
        addr = state.regs.rsi
        print(f"addr of hex string: {addr}")
        for i in range(8):
            print(f"i {i}")
            sym_hex = cl.BVS(f"sym_hex{i}", 64)
            state.memory.store(addr + 8*i, sym_hex)
        print("after loop")
        print(state.memory.load(addr, 64))
        
    return proj, argv


def feconvolve_init(proj):
    # Generate initial state with symbolic values
    var_list = list() 
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x4012ce)
    def setInput1(state):
        print("inside hook")
        addr = state.regs.rsp + 0xb0
        print(f"addr of hex string: {addr}")
        for i in range(12):
            print(f"i {i}")
            sym_hex = cl.BVS(f"sym_hex{i}", 8)
            var_list.append(sym_hex)
            state.memory.store(addr + i, sym_hex)
        print("after loop")
        print(state.memory.load(addr, 12))

    @proj.hook(0x401534)
    def setInput2(state):
        print("inside hook")
        addr = state.regs.rsp + 0xa0
        print(f"addr of hex string: {addr}")
        for i in range(12):
            print(f"i {i+12}")
            sym_hex = cl.BVS(f"sym_hex{i+12}", 8)
            var_list.append(sym_hex)
            state.memory.store(addr + i, sym_hex)
        print("after loop")
        print(state.memory.load(addr, 12))
        print(f"rax: {state.regs.rax}")

    proj.hook_symbol("_Znwm", ReturnZero())        
    return proj, argv, var_list


def feconvolve_init2(proj):
    # Generate initial state with symbolic values
    var_list = list()
    for i in range(12):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x401433)
    #@proj.hook(0x4012cb)
    def setInput1(state):
        print("inside hook")
        #addr = state.regs.rsp + 0x80
        addr = state.regs.rbp - 0x30
        print(f"addr of hex string: {addr}")
        for i in range(12):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF, 8)
            else:
                state.memory.store(addr + i, var_list[i])
        print("after loop")
        print(state.memory.load(addr, 12))

    proj.hook_symbol("_Znwm", ReturnZero())
    proj.hook_symbol("_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc.isra.0", ReturnZero())
    proj.hook_symbol("_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_l", ReturnZero())
    initial_cons = list()
    print(len(var_list))
    print(var_list)
    for i in range(3):
        and1 = cl.And(var_list[i*4]==0, var_list[i*4+1]==0, var_list[i*4+2]==0)
        and2 = cl.And(var_list[i*4]==0xFF, var_list[i*4+1]==0xFF, var_list[i*4+2]==0xFF)
        initial_cons.append(cl.Or(and1, and2))
    return proj, argv, var_list, initial_cons

def feconvolve_init3(proj):
    # Generate initial state with symbolic values
    var_list = list()
    for i in range(12):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x40127c)
    def setInput1(state):
        print("inside hook")
        addr = state.regs.rsp + 0x60
        print(f"addr of hex string: {addr}")
        for i in range(12):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[i])
        print("after loop")
        print(state.memory.load(addr, 12))

    proj.hook_symbol("_Znwm", ReturnZero())
    
    initial_cons = list()
    print(len(var_list))
    print(var_list)
    for i in range(3):
        and1 = cl.And(var_list[i*4]==0, var_list[i*4+1]==0, var_list[i*4+2]==0)
        and2 = cl.And(var_list[i*4]==0xFF, var_list[i*4+1]==0xFF, var_list[i*4+2]==0xFF)
        initial_cons.append(cl.Or(and1, and2))
    return proj, argv, var_list, initial_cons


def feconvolve_init4(proj):
    # Generate initial state with symbolic values
    var_list = list()
    for i in range(12):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x4028f0)
    def setInput1(state):
        print("inside hook")
        addr = state.regs.rbp - 0x38
        print(f"addr of hex string: {addr}")
        for i in range(12):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[i])
        print("after loop")
        print(state.memory.load(addr, 12))

    proj.hook_symbol("_Znwm", ReturnZero())

    initial_cons = list()
    print(len(var_list))
    print(var_list)
    for i in range(3):
        and1 = cl.And(var_list[i*4]==0, var_list[i*4+1]==0, var_list[i*4+2]==0)
        and2 = cl.And(var_list[i*4]==0xFF, var_list[i*4+1]==0xFF, var_list[i*4+2]==0xFF)
        initial_cons.append(cl.Or(and1, and2))
    return proj, argv, var_list, initial_cons


def small_function_init(proj):
    # Generate initial state with symbolic values
    var_list = list()
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x401205)
    def setInput1(state):
        print("inside hook")
        addr = state.regs.rbp - 0x5
        print(f"addr of hex string: {addr}")
        for i in range(4):
            print(f"i {i}")
            sym_hex = cl.BVS(f"sym_hex{i}", 8)
            var_list.append(sym_hex)
            state.memory.store(addr + i, sym_hex)
        print("after loop")
        print(state.memory.load(addr, 4))

    return proj, argv, var_list


def small_function_init2(proj):
    # Generate initial state with symbolic values
    var_list = list()
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x401267)
    def setInput1(state):
        print("inside hook")
        addr = state.regs.rbp - 0x5
        print(f"addr of hex string: {addr}")
        for i in range(1):
            print(f"i {i}")
            sym_hex = cl.BVS(f"sym_hex{i}", 8)
            var_list.append(sym_hex)
            state.memory.store(addr + i, sym_hex)
        print("after loop")
        print(state.memory.load(addr, 1))

    return proj, argv, var_list


def mod_div_init(proj):
    # Generate initial state with symbolic values
    var_list = list()
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x4012e5)
    def setInput1(state):
        print("inside hook")
        addr = state.regs.rbp - 0x5
        print(f"addr of hex string: {addr}")
        for i in range(1):
            print(f"i {i}")
            sym_hex = cl.BVS(f"sym_hex{i}", 8)
            var_list.append(sym_hex)
            state.memory.store(addr + i, sym_hex)
        print("after loop")
        print(state.memory.load(addr, 1))

    return proj, argv, var_list


def mul_shift_add_init(proj):
    # Generate initial state with symbolic values
    var_list = list()
    initial_cons = list()
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x401146)
    def setInput1(state):
        print("inside hook")
        sym1 = cl.BVS(f"sym1", 32)
        sym2 = cl.BVS(f"sym2", 32)
        addr1 = state.regs.rbp - 0x14
        addr2 = state.regs.rbp - 0x10
        state.memory.store(addr1, sym1)
        state.memory.store(addr2, sym2)
        print(state.memory.load(addr1, 4))
        print(state.memory.load(addr2, 4))
        var_list.append(sym1)
        var_list.append(sym2)

    return proj, argv, var_list, initial_cons


def simple_prog_example_init(proj, simulate=False):
    # Generate initial state with symbolic values
    var_list = list()
    initial_cons = list()
    if simulate:
        rand_arg = random.getrandbits(8)
        argv = [proj.filename, str(rand_arg)]
    else:
        argv = [proj.filename, "234"]
    print(f"args: {argv}")
    if not simulate:
        @proj.hook(0x40120e)
        def setInput1(state):
            print("inside hook")
            addr1 = state.regs.rbp - 0x12
            if not simulate:
                sym1 = cl.BVS(f"sym1", 8)
                state.memory.store(addr1, sym1)
                var_list.append(sym1)
            else:
                rand_arg = random.getrandbits(8)
                state.memory.store(addr1, rand_arg)
            print(state.memory.load(addr1, 1))

    return proj, argv, var_list, initial_cons



def helium_eval_ed25519_init(proj, simulate=False):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    argv.append("mqtDnUfdCQYc1uQj")

    # These concretize values for ed25519 key
    k1=list()
    k2=list()
    for i in range(16):
        k1.append(random.getrandbits(32))
    for i in range(8):
        k2.append(random.getrandbits(32))
    proj.hook_symbol('crypto_sign_keypair', generateKeyEd25519(k1=k1, k2=k2))
    return proj, argv


def helium_eval_aesni256gcm_encrypt_init(proj, simulate=False):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    argv.append("mqtDnUfdCQYc1uQj")

    # These concretize values for aes256gcm key and nonce
    k=list()
    n=list()
    for i in range(8):
        k.append(random.getrandbits(32))
    for i in range(3):
        n.append(random.getrandbits(32))
    proj.hook_symbol('crypto_aead_aes256gcm_keybytes', generateKey(k=k))
    proj.hook_symbol('crypto_aead_aes256gcm_npubbytes', generateNonce(n=n))
    return proj, argv



def helium_eval_chacha20_poly1305_encrypt_init(proj, simulate=False):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    argv.append("mqtDnUfdCQYc1uQj")

    # These concretize values for chacha20_poly1305 key and nonce
    k=list()
    n=list()
    for i in range(8):
        k.append(random.getrandbits(32))
    for i in range(3):
        n.append(random.getrandbits(32))
    
    proj.hook_symbol('crypto_aead_chacha20poly1305_ietf_keygen', generateKey(k=k))
    proj.hook_symbol('ciocc_eval_rand_fill_buf', generateNonce(n=n))
    return proj, argv


def helium_eval_argon2id_init(proj, simulate=False):
    # Generate initial state with symbolic values
    argv = [proj.filename]

    SAFE_DEFAULT = (
        string.ascii_lowercase + string.ascii_uppercase + string.digits +
        "!@#$%^&*()-_=+[]{};:,.?/~"  # choose your punctuation set
    )

    def gen_password(length=16, alphabet=SAFE_DEFAULT):
        chars = []
        for _ in range(length):
            ch = secrets.choice(alphabet)
            chars.append(ch)
        return ''.join(chars)

    pwd = ''.join(gen_password(24))
    argv.append(pwd)

    # These concretize values for argon2id salt
    s=list()
    for i in range(8):
        s.append(salt[i])
    proj.hook_symbol('randombytes_buf', generateKey(k=k))
    return proj, argv


def helium_eval_perl_bench(proj, simulate=False):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    argv.append("read_file.pl")
    sp = " "
    print(f"args: {sp.join(argv)}") 
    # These concretize values for chacha20_poly1305 key and nonce
    v=list()
    for i in range(8):
        v.append(random.getrandbits(32))
    return proj, argv


def helium_eval_arith_test(proj, simulate=False):
    # Generate initial state with symbolic values
    argv = [proj.filename]
    
    @proj.hook(0x401226)
    def hook_register(state):
        state.regs.rax = cl.BVS(f"symb", 64)

        print(f"Hooking: rax = {state.regs.rax}")
    return proj, argv

def libjpeg_harness(proj, simulate=False):
    W = 8
    H = 8
    N = W * H * 3  # RGB bytes
    argv = [proj.filename]
    # Symbolic stdin = pixels
    sym_bytes = [cl.BVS(f"b{i}", 8) for i in range(N)]
    sym_stdin = cl.Concat(*sym_bytes)
    concrete = os.urandom(N)
    conc_stdin = cl.BVV(concrete)
    stdin = sym_stdin
    print(f"Hooking stdin: {stdin}")
    st = proj.factory.full_init_state(stdin=stdin)
    return proj, argv, st



def libjpeg_harness_small(proj, simulate=False):
    W = 3
    H = 3
    N = W * H * 3  # RGB bytes
    argv = [proj.filename]
    # Symbolic stdin = pixels
    sym_bytes = [cl.BVS(f"b{i}", 8) for i in range(N)]
    sym_stdin = cl.Concat(*sym_bytes)
    concrete = os.urandom(N)
    conc_stdin = cl.BVV(concrete)
    stdin = sym_stdin
    print(f"Hooking stdin: {stdin}")
    st = proj.factory.full_init_state(stdin=stdin)
    return proj, argv, st


def colorspace_matrix_3x3(proj, simulate=False, W=3, H=3):
    N = W * H * 3  # RGB bytes
    argv = [proj.filename]
    sym_bytes = [cl.BVS(f"b{i}", 8) for i in range(N)]
    sym_stdin = cl.Concat(*sym_bytes)
    concrete = os.urandom(N)
    conc_stdin = cl.BVV(concrete)
    stdin = sym_stdin
    print(f"Hooking nothing")
    return proj, argv

def firefox_box_blur(proj, simulate=False, W=3, H=3):
    N = W * H * 4  # RGBA bytes
    argv = [proj.filename]
    var_list = list()
    for i in range(N):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x401506)
    def setInput1(state):
        print("inside hook 1")
        addr = state.regs.rbp - 0x70
        for i in range(16):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[i])
        print(state.memory.load(addr, 16))

    @proj.hook(0x401522)
    def setInput1(state):
        print("inside hook 2")
        addr = state.regs.rbp - 0x60
        for i in range(16):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[16+i])
        print(state.memory.load(addr, 16))


    @proj.hook(0x401529)
    def setInput1(state):
        print("inside hook 3")
        addr = state.regs.rbp - 0x50
        for i in range(4):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[32+i])
        print(state.memory.load(addr, 4))

    initial_cons = list()
    print(len(var_list))
    print(var_list)
    for i in range(W*H):
       and1 = cl.And(var_list[i*4]==0, var_list[i*4+1]==0, var_list[i*4+2]==0)
       and2 = cl.And(var_list[i*4]==0xFF, var_list[i*4+1]==0xFF, var_list[i*4+2]==0xFF)
       initial_cons.append(cl.Or(and1, and2))
        # initial_cons.append(var_list[i*4]==var_list[i*4+1])
        # initial_cons.append(var_list[i*4+1]==var_list[i*4+2])
    return proj, argv, var_list, initial_cons


def firefox_box_blur_2x2(proj, simulate=False, W=2, H=2):
    N = W * H * 4 # RGBA bytes
    argv = [proj.filename]
    var_list = list()
    for i in range(N):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x401503)
    def setInput1(state):
        print("inside hook 1")
        addr = state.regs.rbp - 0x40
        for i in range(16):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[i])
        print(state.memory.load(addr, 16))

    initial_cons = list()
    print(len(var_list))
    print(var_list)
    for i in range(H*W):
        # and1 = cl.And(var_list[i*4]==0, var_list[i*4+1]==0, var_list[i*4+2]==0)
        # and2 = cl.And(var_list[i*4]==0xFF, var_list[i*4+1]==0xFF, var_list[i*4+2]==0xFF)
        # initial_cons.append(cl.Or(and1, and2))
       initial_cons.append(var_list[i*4]==var_list[i*4+1])
       initial_cons.append(var_list[i*4+1]==var_list[i*4+2])
    return proj, argv, var_list, initial_cons


def firefox_laplacian(proj, simulate=False, W=3, H=3):
    N = W * H * 4  # RGBA bytes
    argv = [proj.filename]
    var_list = list()
    for i in range(N):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x40150c)
    def setInput1(state):
        print("inside hook 1")
        addr = state.regs.rbp - 0xa0
        for i in range(16):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[i])
        print(state.memory.load(addr, 16))

    @proj.hook(0x40152e)
    def setInput1(state):
        print("inside hook 2")
        addr = state.regs.rbp - 0x90
        for i in range(16):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[16+i])
        print(state.memory.load(addr, 16))

    @proj.hook(0x401535)
    def setInput1(state):
        print("inside hook 3")
        addr = state.regs.rbp - 0x80
        for i in range(4):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[32+i])
        print(state.memory.load(addr, 4))

    return proj, argv


def firefox_gaussian_blur(proj, simulate=False, W=3, H=3):
    N = W * H * 4  # RGBA bytes
    argv = [proj.filename]
    var_list = list()
    for i in range(N):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)
    argv = [proj.filename]
    print(f"args: {argv}")
    @proj.hook(0x401506)
    def setInput1(state):
        print("inside hook 1")
        addr = state.regs.rbp - 0x70
        for i in range(16):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[i])
        print(state.memory.load(addr, 16))

    @proj.hook(0x401522)
    def setInput2(state):
        print("inside hook 2")
        addr = state.regs.rbp - 0x60
        for i in range(16):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[16+i])
        print(state.memory.load(addr, 16))

    @proj.hook(0x401529)
    def setInput3(state):
        print("inside hook 3")
        addr = state.regs.rbp - 0x50
        for i in range(4):
            if i % 4 == 3:
                state.memory.store(addr + i, 0xFF)
            else:
                state.memory.store(addr + i, var_list[32+i])
        print(state.memory.load(addr, 4))

    return proj, argv


def firefox_box_blur_general(proj, S='2'):
    argv = [proj.filename, S]
    S = int(S)
    N = S * S * 4  # RGBA bytes
    var_list = list()
    for i in range(N):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)

    print(f"args: {argv}")
    if S == 2:
        @proj.hook(0x401530)
        def setInput1(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0x40
            for i in range(N):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, N))

    elif S == 3:        
        @proj.hook(0x40179b)
        def setInput2(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0x70
            for i in range(16):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x60
            for i in range(16):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[16+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x50
            for i in range(4):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[32+i])
            print(state.memory.load(addr, 4))
    
    elif S == 4:
        @proj.hook(0x401afe)
        def setInput3(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0xa0
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x90
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[16+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x80
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[32+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x70
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[48+i])
            print(state.memory.load(addr, 16))


    initial_cons = list()
    for i in range(S*S):
        and1 = cl.And(var_list[i*4]==0, var_list[i*4+1]==0, var_list[i*4+2]==0)
        and2 = cl.And(var_list[i*4]==0xFF, var_list[i*4+1]==0xFF, var_list[i*4+2]==0xFF)
        initial_cons.append(cl.Or(and1, and2))
        # initial_cons.append(var_list[i*4]==var_list[i*4+1])
        # initial_cons.append(var_list[i*4+1]==var_list[i*4+2])
    return proj, argv, var_list, initial_cons


def firefox_bitwise(proj, S='2'):
    argv = [proj.filename, S]
    S = int(S)
    N = S * S * 4  # RGBA bytes
    var_list = list()
    for i in range(N):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)

    print(f"args: {argv}")
    if S == 2:
        @proj.hook(0x401c21)
        def setInput1(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0x20
            for i in range(N):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, N))

    elif S == 3:        
        @proj.hook(0x401d8d)
        def setInput2(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0x30
            for i in range(16):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x20
            for i in range(16):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[16+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x10
            for i in range(4):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[32+i])
            print(state.memory.load(addr, 4))
    
    elif S == 4:
        @proj.hook(0x401f2a)
        def setInput3(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0x50
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x40
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[16+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x30
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[32+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x20
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[48+i])
            print(state.memory.load(addr, 16))


    initial_cons = list()
    for i in range(S*S):
        and1 = cl.And(var_list[i*4]==0, var_list[i*4+1]==0, var_list[i*4+2]==0)
        and2 = cl.And(var_list[i*4]==0xFF, var_list[i*4+1]==0xFF, var_list[i*4+2]==0xFF)
        initial_cons.append(cl.Or(and1, and2))
        # initial_cons.append(var_list[i*4]==var_list[i*4+1])
        # initial_cons.append(var_list[i*4+1]==var_list[i*4+2])
    return proj, argv, var_list, initial_cons


def firefox_box_blur_general(proj, S='2'):
    argv = [proj.filename, S]
    S = int(S)
    N = S * S * 4  # RGBA bytes
    var_list = list()
    for i in range(N):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)

    print(f"args: {argv}")
    if S == 2:
        @proj.hook(0x401530)
        def setInput1(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0x40
            for i in range(N):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, N))

    elif S == 3:        
        @proj.hook(0x40179b)
        def setInput2(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0x70
            for i in range(16):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x60
            for i in range(16):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[16+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x50
            for i in range(4):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[32+i])
            print(state.memory.load(addr, 4))
    
    elif S == 4:
        @proj.hook(0x401afe)
        def setInput3(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0xa0
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x90
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[16+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x80
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[32+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x70
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[48+i])
            print(state.memory.load(addr, 16))


    initial_cons = list()
    for i in range(S*S):
        and1 = cl.And(var_list[i*4]==0, var_list[i*4+1]==0, var_list[i*4+2]==0)
        and2 = cl.And(var_list[i*4]==0xFF, var_list[i*4+1]==0xFF, var_list[i*4+2]==0xFF)
        initial_cons.append(cl.Or(and1, and2))
        # initial_cons.append(var_list[i*4]==var_list[i*4+1])
        # initial_cons.append(var_list[i*4+1]==var_list[i*4+2])
    return proj, argv, var_list, initial_cons


def img_transform_kernels(proj, S='2'):
    argv = [proj.filename, S]
    S = int(S)
    N = S * S * 4  # RGBA bytes
    var_list = list()
    for i in range(N):
        sym_hex = cl.BVS(f"sym_hex{i}", 8)
        var_list.append(sym_hex)

    print(f"args: {argv}")
    if S == 2:
        @proj.hook(0x402021)
        def setInput1(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0x30
            for i in range(N):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, N))

    elif S == 3:        
        @proj.hook(0x4022ba)
        def setInput2(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0x60
            for i in range(16):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x50
            for i in range(16):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[16+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x40
            for i in range(4):
                if i % 4 == 3:
                    state.memory.store(addr + i, 0xFF, 1)
                    # continue
                else:
                    state.memory.store(addr + i, var_list[32+i])
            print(state.memory.load(addr, 4))
    
    elif S == 4:
        @proj.hook(0x4025cc)
        def setInput3(state):
            print("inside hook 1")
            addr = state.regs.rbp - 0x90
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x80
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[16+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x70
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[32+i])
            print(state.memory.load(addr, 16))

            addr = state.regs.rbp - 0x60
            for i in range(16):
                if i % 4 == 3:
                    continue
                else:
                    state.memory.store(addr + i, var_list[48+i])
            print(state.memory.load(addr, 16))


    initial_cons = list()
    for i in range(S*S):
        and1 = cl.And(var_list[i*4]==0, var_list[i*4+1]==0, var_list[i*4+2]==0)
        and2 = cl.And(var_list[i*4]==0xFF, var_list[i*4+1]==0xFF, var_list[i*4+2]==0xFF)
        initial_cons.append(cl.Or(and1, and2))
        # initial_cons.append(var_list[i*4]==var_list[i*4+1])
        # initial_cons.append(var_list[i*4+1]==var_list[i*4+2])
    return proj, argv, var_list, initial_cons


def default(proj, S=None, simulate=False):
    argv = [proj.filename]
    if S is not None:
        argv.append(S)
    print(f"Hooking nothing")
    return proj, argv

