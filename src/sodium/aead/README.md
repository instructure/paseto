# Aead #

Handles the wrapping of libsdoium for everything "aead". This techincally could
just be one (since we only export one item), but we've added it to a directory
incase we need to add more functions at any point (and haven't switched libraries yet).

Just like it's parent directory you shouldn't need to interact with this directly, but
it could be useful for looking at how we do our aead encryption.
