# EFF Large Wordlist

## Important Note

The current wordlist in `eff_large_wordlist.txt` is a placeholder for development and testing purposes only.

**For production use, you MUST replace this with the authentic EFF large wordlist.**

## How to Install the Real EFF Wordlist

1. Download the official EFF large wordlist:
   ```bash
   curl -o eff_large_wordlist.txt https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
   ```

2. Extract only the words (remove dice numbers):
   ```bash
   cut -f2 eff_large_wordlist.txt > wordlist_words_only.txt
   mv wordlist_words_only.txt eff_large_wordlist.txt
   ```

3. Or use this Python script:
   ```python
   import urllib.request
   
   url = "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt"
   
   # Download wordlist
   with urllib.request.urlopen(url) as response:
       content = response.read().decode('utf-8')
   
   # Extract words only (second column)
   words = [line.split('\t')[1] for line in content.strip().split('\n')]
   
   # Write to file
   with open('eff_large_wordlist.txt', 'w') as f:
       for word in words:
           f.write(word + '\n')
   ```

## About the EFF Large Wordlist

The EFF (Electronic Frontier Foundation) large wordlist contains 7,776 words optimized for creating secure, memorable passphrases using the Diceware method.

**Key properties:**
- Exactly 7,776 words (6⁵ = 7,776 for 5 dice rolls)
- Each word is 3-9 characters long
- Words are chosen to be memorable and easy to type
- No homophones, profanity, or overly similar words
- Provides ~12.925 bits of entropy per word

**Security:**
A 6-word passphrase provides ~77.5 bits of entropy, equivalent to a 14-character random password using all character classes.

## References

- [EFF Dice-Generated Passphrases](https://www.eff.org/dice)
- [EFF Large Wordlist](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt)
- [Diceware Method](http://world.std.com/~reinhold/diceware.html)

## License

The EFF wordlist is licensed under Creative Commons Attribution 3.0 United States.
