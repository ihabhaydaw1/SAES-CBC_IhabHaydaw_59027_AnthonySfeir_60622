import saes

key = 0xA73B
pt = 0x6F6B

keys = saes.key_expansion(key)
print([hex(k) for k in keys])

state = saes.add_round_key(pt, keys[0])
print("R0 AddKey:", hex(state))

state = saes.nibble_substitution(state, saes.SBOX)
print("R1 SubNibbles:", hex(state))

state = saes.shift_rows(state)
print("R1 ShiftRows:", hex(state))

state = saes.mix_columns(state, is_inverse=False)
print("R1 MixColumns:", hex(state))

state = saes.add_round_key(state, keys[1])
print("R1 AddKey:", hex(state))

state = saes.nibble_substitution(state, saes.SBOX)
print("R2 SubNibbles:", hex(state))

state = saes.shift_rows(state)
print("R2 ShiftRows:", hex(state))

state = saes.add_round_key(state, keys[2])
print("R2 AddKey (CT):", hex(state))
