// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef XENGINE_STRUCTURE_TREE_H
#define XENGINE_STRUCTURE_TREE_H

#include <map>
#include <memory>
#include <set>

namespace xengine
{

template <typename K, typename D>
class CTreeNode
{
public:
    typedef std::shared_ptr<CTreeNode> NodePtr;

    K key;
    D data;
    NodePtr pParent;
    std::set<NodePtr> setChildren;

    CTreeNode()
    {
    }

    CTreeNode(const K& keyIn)
      : key(keyIn)
    {
    }

    CTreeNode(const K& keyIn, const D& dataIn)
      : key(keyIn), data(dataIn)
    {
    }
};

template <typename K, typename D>
class CMultiwayTree
{
public:
    typedef std::shared_ptr<CMultiwayTree> TreePtr;
    typedef typename CTreeNode<K, D>::NodePtr NodePtr;
    NodePtr pRoot;

    // postorder traversal
    // walker: bool (*function)(std::weak_ptr<CTreeNode<D>>)
    template <typename NodeWalker>
    bool PostorderTraversal(NodeWalker walker)
    {
        NodePtr pNode = pRoot;

        // postorder traversal
        std::stack<NodePtr> st;
        do
        {
            // if pNode != nullptr push and down, or pop and up.
            if (pNode != nullptr)
            {
                if (!pNode->setSubline.empty())
                {
                    st.push(pNode);
                    pNode = *pNode->setSubline.begin();
                    continue;
                }
            }
            else
            {
                pNode = st.top();
                st.pop();
            }

            // call walker
            if (!walker(pNode))
            {
                return false;
            }

            // root or the last child of parent. fetch from stack when next loop
            if (pNode->pParent == nullptr || pNode == *pNode->pParent->setSubline.rbegin())
            {
                pNode = nullptr;
            }
            else
            {
                auto it = pNode->pParent->setSubline.find(pNode);
                if (it == pNode->pParent->setSubline.end())
                {
                    return false;
                }
                else
                {
                    pNode = *++it;
                }
            }
        } while (!st.empty());

        return true;
    }
};

template <typename K, typename D>
class CForest
{
public:
    typedef typename CTreeNode<K, D>::NodePtr NodePtr;
    typedef typename CMultiwayTree<K, D>::TreePtr TreePtr;

    std::map<K, NodePtr> mapNode;
    std::map<K, TreePtr> mapRoot;

    CForest() {}
    ~CForest() {}

    // postorder traversal
    // walker: bool (*function)(std::weak_ptr<CTreeNode<D>>)
    template <typename NodeWalker>
    bool PostorderTraversal(NodeWalker walker)
    {
        for (auto& r : mapRoot)
        {
            if (!r.second->PostorderTraversal(walker))
            {
                return false;
            }
        }
        return true;
    }

    bool Check(const K& key, const K& parent, const D& data)
    {
        NodePtr pNode = GetRelation(key);
        if (pNode)
        {
            // already have parent
            if (pNode->pParent)
            {
                return false;
            }

            // cyclic graph
            for (NodePtr p = GetRelation(parent); p; p = p->pParent)
            {
                if (p->data == data)
                {
                    return false;
                }
            }
        }

        return true;
    }

    bool
    Insert(const K& key, const K& parent, const D& data)
    {
        if (!Check(key, parent, data))
        {
            return false;
        }

        // parent
        auto im = mapNode.find(parent);
        if (im == mapNode.end())
        {
            im = mapNode.insert(make_pair(parent, NodePtr(new CTreeNode<K, D>(parent)))).first;
            mapRoot.insert(make_pair(parent, im->second));
        }

        // self
        auto it = mapNode.find(key);
        if (it == mapNode.end())
        {
            it = mapNode.insert(make_pair(key, NodePtr(new CTreeNode<K, D>(key, data)))).first;
        }
        else
        {
            mapRoot.erase(key);
        }

        it->second->pParent = im->second;
        im->second->setSubline.insert(it->second);

        return true;
    }

    void RemoveRelation(const K& key)
    {
        auto it = mapNode.find(key);
        if (it == mapNode.end())
        {
            return;
        }

        NodePtr pNode = it->second;
        NodePtr pParent = pNode->pParent;
        if (pParent)
        {
            pParent->setSubline.erase(pNode);
            // parent is root and no subline
            if (pParent->setSubline.empty() && !pParent->pParent)
            {
                mapRoot.erase(pParent->key);
                mapNode.erase(pParent->key);
            }

            pNode->pParent = nullptr;
            if (!pNode->setSubline.empty())
            {
                mapRoot.insert(make_pair(key, pNode));
            }
            else
            {
                mapNode.erase(pParent->key);
            }
        }
    }

    NodePtr GetRelation(const K& key)
    {
        auto it = mapNode.find(key);
        return (it == mapNode.end()) ? nullptr : it->second;
    }

}; // namespace xengine

} // namespace xengine

#endif // XENGINE_STRUCTURE_TREE_H