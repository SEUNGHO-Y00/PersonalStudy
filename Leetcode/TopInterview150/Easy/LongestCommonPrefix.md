# Longest Common Prefix

## Question

Write a function to find the longest common prefix string amongst an array of strings.

If there is no common prefix, return an empty string "".

Example 1:

- Input: strs = ["flower","flow","flight"]
- Output: "fl"

Example 2:

- Input: strs = ["dog","racecar","car"]
- Output: ""
- Explanation: There is no common prefix among the input strings.

## Answer

```python
def longestCommonPrefix(self, strs: List[str]) -> str:
    prefix=""
    voca=sorted(strs)
    first=voca[0]
    last=voca[-1]
    for i in range(min(len(first),len(last))):
        if(first[i]!=last[i]):
            return prefix
        prefix += first[i]
    return prefix
```
