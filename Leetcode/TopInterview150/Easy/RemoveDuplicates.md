# Remove Duplicates from Sorted Array

## Question

* Given an integer array nums sorted in non-decreasing order, remove the duplicates in-place such that each unique element appears only once. The relative order of the elements should be kept the same. Then return the number of unique elements in nums.

* Consider the number of unique elements of nums to be k, to get accepted, you need to do the following things:

* Change the array nums such that the first k elements of nums contain the unique elements in the order they were present in nums initially. The remaining elements of nums are not important as well as the size of nums.

* Return k.

## Answer

```python
    def removeDuplicates(self, nums: List[int]) -> int:
        if not nums: # Handle empty list case
            return 0
        
        k = 0 # Ponter for the position of unique elements
        for i in range(1, len(nums)):
            if nums[k] != nums[i]:
                k += 1 # move to the next position
                nums[k] = nums [i]

        return k + 1 # return unique lements
```

## The other Answer

```python
        i=0
        for j in range(0,len(nums)):     
            if(nums[j]!=nums[i]):
                nums[i+1]=nums[j]
                i+=1
        return i+1       
```
