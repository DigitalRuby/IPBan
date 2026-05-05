/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Measures the difference between two strings.
    /// Uses the Levenshtein string difference algorithm.
    /// </summary>
    public static class LevenshteinUnsafe
    {
        /// <summary>
        /// Maximum input length accepted for either string. Inputs longer than this are rejected
        /// to prevent unbounded stackalloc / CPU consumption on attacker-controlled values.
        /// </summary>
        public const int MaxInputLength = 1024;

        /// <summary>
        /// Threshold (in elements) below which we use stackalloc; at or above this we fall back
        /// to a heap-allocated buffer so we never blow the stack.
        /// </summary>
        private const int StackAllocThreshold = 256;

        /// <summary>
        /// Compares the two values to find the minimum Levenshtein distance.
        /// Thread safe.
        /// </summary>
        /// <returns>Difference. 0 complete match. -1 if either value1 or value2 is null, -2 if either value is too large.</returns>
        public static unsafe int Distance(string value1, string value2)
        {
            if (value1 is null || value2 is null)
            {
                return -1;
            }
            else if (value1.Length > MaxInputLength || value2.Length > MaxInputLength)
            {
                // bound input to prevent uncatchable StackOverflowException from a hostile string
                return -2;
            }
            else if (value2.Length == 0)
            {
                return value1.Length;
            }
            else if (value1.Length == 0)
            {
                return value2.Length;
            }

            // small inputs go on the stack (fast path); larger inputs use a heap buffer pinned
            // for the duration of the call so the unsafe pointer math stays valid.
            if (value2.Length < StackAllocThreshold)
            {
                int* costs = stackalloc int[value2.Length];
                return DistanceCore(value1, value2, costs);
            }
            else
            {
                int[] heapCosts = new int[value2.Length];
                fixed (int* costs = heapCosts)
                {
                    return DistanceCore(value1, value2, costs);
                }
            }
        }

        private static unsafe int DistanceCore(string value1, string value2, int* costs)
        {
            int* costsEnd = costs + value2.Length, ptr;
            int i = 0, j, insertionCost, cost, additionCost;
            char value1Char;

            for (ptr = costs; ptr != costsEnd; ptr++)
            {
                *ptr = ++i;
            }

            for (i = 0; i < value1.Length; i++)
            {
                // cost of the first index
                cost = additionCost = i;

                // cache value for inner loop to avoid index lookup and bounds checking, profiled this is quicker
                value1Char = value1[i];

                for (ptr = costs, j = 0; ptr != costsEnd; ptr++, j++)
                {
                    insertionCost = cost;
                    cost = additionCost;

                    // assigning this here reduces the array reads we do, improvement of the old version
                    additionCost = *ptr;

                    if (value1Char != value2[j])
                    {
                        if (insertionCost < cost)
                        {
                            cost = insertionCost;
                        }

                        if (additionCost < cost)
                        {
                            cost = additionCost;
                        }

                        ++cost;
                    }

                    *ptr = cost;
                }
            }

            // the last int is the cost
            return *(--costsEnd);
        }
    }
}
