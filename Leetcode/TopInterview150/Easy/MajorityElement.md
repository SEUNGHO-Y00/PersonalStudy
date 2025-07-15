# Majority Element

## Question

Given an array nums of size n, return the majority element.

The majority element is the element that appears more than ⌊n / 2⌋ times. You may assume that the majority element always exists in the array.

## Answer

```python
def majorityElement(self, nums: List[int]) -> int:
    nums.sort()
    n = len(nums)
    return nums[n//2]
```
