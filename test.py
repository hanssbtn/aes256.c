def m(a: int, b: int):
	c = 0
	i = 0
	while i < 8:
		c ^= b * (a & (1 << i))
		i = i + 1

	i = 15
	while i > 0:
		if (c & (1 << i)):
			print(f"x^{i}", end="")
			i = i - 1
			break
		i = i - 1
	
	while i > 0:
		if (c & (1 << i)):
			print(" + ", end="")
			print(f"x^{i}", end="")
		i = i - 1
	print(f"{" + 1" if (c & 1) else ""}")
	
	m = 0x11b
	i = 15
	while c >= m:
		c ^= m * (c & (1 << i) > 0) << (i - 8)
		i = i - 1
	
	i = 15
	while i > 0:
		if (c & (1 << i)):
			print(f"x^{i}", end="")
			i = i - 1
			break
		i = i - 1
		
	while i > 0:
		if (c & (1 << i)):
			print(" + ", end="")
			print(f"x^{i}", end="")
		i = i - 1
	print(f"{" + 1" if (c & 1) else ""}")

# m(0x83, 0x57)
# m(0x83, 0x01)
# m(0x7, 0x3)

def k(a, b):
	p = 0
	for _ in range(8):
		# If the least significant bit (LSB) of `b` is 1, we need to add
		# (which is XOR in GF(2)) the first multiplicand `a` to the product `p`.
		if b & 1:
			p ^= a

		# Now, we need to prepare for the next bit of `b`. This involves
		# doubling `a` (left-shifting) in the Galois Field.
		# First, check if the most significant bit (MSB) of `a` is 1.
		# This is equivalent to checking if the polynomial `a` has an x^7 term.
		is_msb_set = (a & 0x80) != 0
		
		# Left-shift `a` by 1. This is equivalent to multiplying by x.
		a <<= 1
		
		# If the MSB was set before the shift, the new `a` would be > 255,
		# which means it's a polynomial of degree 8 and needs to be reduced.
		# We reduce it by XORing with the irreducible polynomial (0x1B).
		if is_msb_set:
			a ^= 0x1B

		# Right-shift `b` by 1 to process its next bit in the following loop iteration.
		b >>= 1
		
	# The final product `p` must be within 8 bits. We use a mask to ensure this,
	# though the algorithm naturally keeps it within this range.
	return p & 0xFF

def bdiv(a: int, b: int) -> int:
	if a == 0 or a < b:
		return 0
	c: int = 0
	while a.bit_length() >= b.bit_length():
		print(f"{a.bit_length()=}")
		print(f"{b.bit_length()=}")
		s: int = a.bit_length() - b.bit_length()
		c |= 1 << s
		a ^= b << s
	return c

def bmul(a: int, b: int) -> int:
	c = 0
	while b > 0:
		if (b & 1):
			c ^= a
		b >>= 1
		a <<= 1
	print(f"{a=},{b=},{c=}")
	return c

def inv(a: int) -> int:
	t, newt = 0, 1
	r, newr = 0x11b, a

	while newr != 0:
		q = bdiv(r, newr)
		tmp = t
		t = newt
		newt = tmp ^ bmul(newt, q)
		tmp = r
		r = newr
		newr = tmp ^ bmul(newr, q)
		# t, newt = newt, t ^ bmul(newt, q)
		# r, newr = newr, r ^ bmul(newr, q)
		print(t, r, q, newr, newt)
	print(f"{t=}")
	return t

for i in range(1, 256):
	assert k(i, inv(i)) == 1, f"i: {i}, inv(i): {inv(i)}, k(i, inv(i)): {k(i, inv(i))}"